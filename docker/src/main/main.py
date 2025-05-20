import asyncio
from typing import Annotated, Self

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .cli import Cli as DockerCli
from .build import Build
from .sbom import Sbom


@object_type
class Docker:
    """Docker"""

    workdir: dagger.Directory
    image: str
    version: str
    user: str

    container_: dagger.Container
    docker_: DockerCli | None

    @classmethod
    async def create(
        cls,
        workdir: Annotated[
            dagger.Directory | None,
            DefaultPath("."),
            Doc("Working dir"),
            Name("source"),
        ],
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Docker CLI version")] = "latest",
        user: Annotated[str | None, Doc("Image user")] = "nonroot",
    ):
        """Constructor"""
        return cls(
            workdir=workdir,
            image=image,
            version=version,
            user=user,
            container_=dag.container(),
            docker_=None,
        )

    @function
    def docker(self) -> DockerCli:
        """Returns the Apko CLI"""
        if self.docker_:
            return self.docker_
        self.docker_ = DockerCli(
            image=self.image, user=self.user, version=self.version, workdir=self.workdir
        )
        return self.docker_

    @function
    def container(self) -> dagger.Container:
        """Returns the docker container"""
        return self.docker().container()

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.docker_ = self.docker().with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    def with_env_variable(
        self,
        name: Annotated[str, Doc("Name of the environment variable")],
        value: Annotated[str, Doc("Value of the environment variable")],
        expand: Annotated[
            bool | None,
            Doc(
                "Replace “${VAR}” or “$VAR” in the value according to the current environment variables defined in the container"
            ),
        ] = False,
    ) -> Self:
        """Set a new environment variable in the Apko container"""
        self.docker_ = self.docker().with_env_variable(
            name=name, value=value, expand=expand
        )
        return self

    @function
    def with_secret_variable(
        self,
        name: Annotated[str, Doc("Name of the secret variable")],
        secret: Annotated[dagger.Secret, Doc("Identifier of the secret value")],
    ) -> Self:
        """Set a new environment variable, using a secret value"""
        self.docker_ = self.docker().with_secret_variable(name=name, secret=secret)
        return self

    @function
    def with_unix_socket(
        self,
        source: Annotated[dagger.Socket, Doc("Identifier of the socket to forward")],
    ) -> Self:
        """Retrieves the Apko container plus a socket forwarded to the given Unix socket path"""
        self.docker_ = self.docker().with_unix_socket(source=source)
        return self

    @function
    async def build(
        self,
        dockerfile: Annotated[
            str | None, Doc("Location of the Dockerfile")
        ] = "Dockerfile",
        target: Annotated[str | None, Doc("Set the target build stage to build")] = "",
        build_args: Annotated[
            list[str] | None,
            Doc("Build args to pass to the build in the format of name=value"),
            Name("build_arg"),
        ] = (),
        secrets: Annotated[
            list[dagger.Secret] | None,
            Doc("Secrets to pass to the build"),
            Name("secret"),
        ] = (),
        platforms: Annotated[
            list[dagger.Platform] | None,
            Doc("Set target platform for build"),
            Name("platform"),
        ] = (),
        sbom: Annotated[bool | None, Doc("generate SBOM")] = True,
    ) -> Build:
        """Build multi-arch OCI image"""
        current_platform: dagger.Platform = await self.container_.platform()
        platform_variants: list[dagger.Container] = []
        dagger_build_args: list[dagger.BuildArg] = []
        sboms: list[dagger.File] = []

        async def build_(
            platform: dagger.Platform,
            dockerfile: str,
            target: str,
            build_args: list[dagger.BuildArg],
            secrets: list[dagger.Secret],
        ):
            container: dagger.Container = dag.container(platform=platform)
            if platform == current_platform:
                container = self.container_

            container = await container.build(
                context=self.workdir,
                dockerfile=dockerfile,
                target=target,
                build_args=build_args,
                secrets=secrets,
            )
            if platform == current_platform:
                self.container_ = container
            else:
                platform_variants.append(container)

        for build_arg in build_args:
            build_arg_split = build_arg.split("=")
            dagger_build_args.append(
                dagger.BuildArg(name=build_arg_split[0], value=build_arg_split[1])
            )

        if platforms:
            async with asyncio.TaskGroup() as tg:
                for platform in platforms:
                    tg.create_task(
                        build_(
                            platform=platform,
                            dockerfile=dockerfile,
                            target=target,
                            build_args=dagger_build_args,
                            secrets=secrets,
                        )
                    )
        else:
            self.container_ = self.container_.build(
                context=self.workdir,
                dockerfile=dockerfile,
                target=target,
                build_args=dagger_build_args,
                secrets=secrets,
            )

        # Generates SBOMs for each platform
        if sbom:
            platform_variants_tarball: dagger.File = self.container_.as_tarball(
                platform_variants=platform_variants
            )
            for platform in platforms or [current_platform]:
                tarball: dagger.File = (
                    dag.container(platform=platform)
                    .import_(source=platform_variants_tarball)
                    .as_tarball()
                )
                sbom_path: str = (
                    f"$DOCKER_SBOM_DIR/sbom-{platform.replace('/', '-')}.spdx.json"
                )
                sboms.append(
                    self.container()
                    .with_mounted_file(
                        "/tmp/image.tar", source=tarball, owner=self.docker().user
                    )
                    .with_exec(
                        [
                            "syft",
                            "scan",
                            "oci-archive:/tmp/image.tar",
                            "--output",
                            f"spdx-json={sbom_path}",
                        ],
                        expand=True,
                    )
                    .file(path=sbom_path, expand=True)
                )

        return Build(
            container_=self.container_,
            platform_variants=platform_variants,
            docker=self.docker(),
            sbom_=Sbom(
                directory_=self.container()
                .with_files(
                    "$DOCKER_SBOM_DIR",
                    sources=sboms,
                    owner=self.docker().user,
                    expand=True,
                )
                .directory("$DOCKER_SBOM_DIR", expand=True)
            ),
        )
