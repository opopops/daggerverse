from typing import Annotated, Self
from datetime import datetime

import dagger
from dagger import Doc, Name, dag, function, object_type

from .cli import Cli as ApkoCli
from .build import Build
from .config import Config
from .image import Image
from .sbom import Sbom


@object_type
class Apko:
    """Apko module"""

    image: str
    version: str
    user: str

    container_: dagger.Container
    workdir: dagger.Directory | None = None
    apko_: ApkoCli | None = None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Apko version")] = "0.30.29",
        user: Annotated[str | None, Doc("Image user")] = "nonroot",
        workdir: Annotated[
            dagger.Directory | None, Doc("Work directory"), Name("source")
        ] = None,
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            workdir=workdir,
            container_=dag.container(),
            apko_=None,
        )

    @function
    def apko(self) -> ApkoCli:
        """Returns the Apko CLI"""
        if self.apko_:
            return self.apko_
        self.apko_ = ApkoCli(
            image=self.image, user=self.user, version=self.version, workdir=self.workdir
        )
        return self.apko_

    @function
    def source(self) -> dagger.Directory:
        """Returns the work directory"""
        return self.workdir

    @function
    def container(self) -> dagger.Container:
        """Returns the Apko container"""
        return self.apko().container()

    @function
    def config(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        workdir: Annotated[
            dagger.Directory | None, Doc("Work directory"), Name("source")
        ] = None,
    ) -> Config:
        """Returns the derived Apko config"""

        return Config(config=config, apko=self.apko(), workdir=workdir or self.workdir)

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.apko_ = self.apko().with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    def docker_config(self) -> dagger.File:
        """Returns the Docker config file"""
        return self.apko().docker_config()

    @function
    def with_docker_config(
        self, docker_config: Annotated[dagger.File, Doc("Docker config file")]
    ) -> Self:
        """Set Docker config file (for chaining)"""
        self.apko_ = self.apko().with_docker_config(docker_config)
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
        self.apko_ = self.apko().with_env_variable(
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
        self.apko_ = self.apko().with_secret_variable(name=name, secret=secret)
        return self

    @function
    def with_docker_socket(
        self,
        source: Annotated[
            dagger.Socket, Doc("Identifier of the Docker socket to forward")
        ],
    ) -> Self:
        """Retrieves the Apko container plus a socket forwarded to the given Unix socket path"""
        self.apko_ = self.apko().with_docker_socket(source=source)
        return self

    @function
    async def build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        tag: Annotated[str | None, Doc("Image tag")] = "apko-build",
        workdir: Annotated[
            dagger.Directory | None, Doc("Work directory"), Name("source")
        ] = None,
        includes: Annotated[
            list[dagger.Directory] | None,
            Doc("Additional include paths where to look for input files"),
            Name("include-paths"),
        ] = (),
        keyrings: Annotated[
            list[dagger.File] | None,
            Doc("Path to extra keys to include in the keyring"),
            Name("keyring-append"),
        ] = (),
        repositories: Annotated[
            list[dagger.Directory] | None,
            Doc("Path to extra repositories to include"),
            Name("repository-append"),
        ] = (),
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = (),
    ) -> Build:
        """Build an image using Apko"""
        current_platform: dagger.Platform = await self.container_.platform()

        apko = (
            self.apko()
            .container()
            .with_mounted_file(
                path="/tmp/apko.yaml",
                source=config,
                owner=self.user,
            )
        )

        if workdir:
            apko = apko.with_mounted_directory(
                "$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )

        cmd = [
            "build",
            "/tmp/apko.yaml",
            tag,
            "${APKO_BUILD_DIR}/image.tar",
            "--sbom-path",
            "${APKO_BUILD_DIR}",
            "--cache-dir",
            "${APKO_CACHE_DIR}",
        ]

        for index, include in enumerate(includes):
            path: str = f"/tmp/sources/{index}"
            apko = apko.with_mounted_directory(
                path,
                source=include,
                owner=self.user,
            )
            cmd.extend(["--include-paths", path])

        for keyring in keyrings:
            path: str = f"/tmp/keyrings/{await keyring.name()}"
            apko = apko.with_mounted_file(
                path,
                source=keyring,
                owner=self.user,
            )
            cmd.extend(["--keyring-append", path])

        for index, repository in enumerate(repositories):
            path: str = f"/tmp/repositories/{index}"
            apko = apko.with_mounted_directory(
                path,
                source=repository,
                owner=self.user,
            )
            cmd.extend(["--repository-append", path])

        platforms = platforms or [current_platform]
        for platform in platforms:
            cmd.extend(["--arch", platform.split("/")[1]])

        apko = await apko.with_exec(cmd, use_entrypoint=True, expand=True)
        tarball = apko.file("${APKO_BUILD_DIR}/image.tar", expand=True)
        platform_variants: list[dagger.Container] = []
        for platform in platforms:
            if platform == current_platform:
                self.container_ = self.container_.import_(tarball)
            else:
                platform_variants.append(
                    dag.container(platform=platform).import_(tarball)
                )

        return Build(
            tarball_=tarball,
            container_=self.container_,
            platform_variants=platform_variants,
            sbom_=Sbom(
                directory_=apko.directory("${APKO_BUILD_DIR}", expand=True).filter(
                    include=["sbom-*.json"]
                )
            ),
            apko=self.apko(),
        )

    @function
    async def publish(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")],
        workdir: Annotated[
            dagger.Directory | None, Doc("Work directory"), Name("source")
        ] = None,
        includes: Annotated[
            list[dagger.Directory] | None,
            Doc("Additional include paths where to look for input files"),
            Name("include-paths"),
        ] = (),
        keyrings: Annotated[
            list[dagger.File] | None,
            Doc("Path to extra keys to include in the keyring"),
            Name("keyring-append"),
        ] = (),
        repositories: Annotated[
            list[dagger.Directory] | None,
            Doc("Path to extra repositories to include"),
            Name("repository-append"),
        ] = (),
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = (),
        sbom: Annotated[bool | None, Doc("generate SBOM")] = True,
        local: Annotated[
            bool | None, Doc("Publish image just to local Docker daemon")
        ] = False,
        force: Annotated[
            bool | None, Doc("Force image publishing (invalidate cache)")
        ] = False,
    ) -> Image:
        """Publish an image using Apko"""
        current_platform: dagger.Platform = await self.container_.platform()

        apko = (
            self.apko()
            .container()
            .with_mounted_file(
                path="/tmp/apko.yaml",
                source=config,
                owner=self.user,
            )
        )

        if workdir:
            apko = apko.with_mounted_directory(
                "$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )

        if force:
            # Cache buster
            apko = apko.with_env_variable("CACHEBUSTER", str(datetime.now()))

        cmd = ["publish", "/tmp/apko.yaml"]

        cmd.extend(tags)
        cmd.extend(["--cache-dir", "$APKO_CACHE_DIR"])

        for index, include in enumerate(includes):
            path: str = f"/tmp/sources/{index}"
            apko = apko.with_mounted_directory(
                path,
                source=include,
                owner=self.user,
            )
            cmd.extend(["--include-paths", path])

        for index, keyring in enumerate(keyrings):
            path: str = f"/tmp/keyrings/{index}"
            apko = apko.with_mounted_file(
                path,
                source=keyring,
                owner=self.user,
            )
            cmd.extend(["--keyring-append", path])

        for index, repository in enumerate(repositories):
            path: str = f"/tmp/repositories/{index}"
            apko = apko.with_mounted_directory(
                path,
                source=repository,
                owner=self.user,
            )
            cmd.extend(["--repository-append", path])

        if sbom:
            cmd.extend(["--sbom=true", "--sbom-path", "$APKO_BUILD_DIR"])
        else:
            cmd.append("--sbom=false")

        platforms = platforms or [current_platform]
        for platform in platforms:
            cmd.extend(["--arch", platform.split("/")[1]])

        if local:
            cmd.append("--local")

        # Publish the container
        apko = apko.with_exec(cmd, use_entrypoint=True, expand=True)
        address: str = (await apko.stdout()).strip()

        return Image(
            address=address,
            container_=self.container().from_(address)
            if not local
            else self.container(),
            sbom_=Sbom(
                directory_=apko.directory("$APKO_BUILD_DIR", expand=True).filter(
                    include=["sbom-*.json"]
                )
            ),
            apko=self.apko(),
        )
