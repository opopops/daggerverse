from typing import Annotated, Self
from datetime import datetime

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .cli import Cli as ApkoCli
from .build import Build
from .config import Config
from .image import Image
from .sbom import Sbom


@object_type
class Apko:
    """Apko module"""

    workdir: dagger.Directory
    image: str
    version: str
    user: str

    container_: dagger.Container
    apko_: ApkoCli | None

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
        version: Annotated[str | None, Doc("Apko version")] = "latest",
        user: Annotated[str | None, Doc("Image user")] = "nonroot",
    ):
        """Constructor"""
        return cls(
            workdir=workdir,
            image=image,
            version=version,
            user=user,
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
    def container(self) -> dagger.Container:
        """Returns the Apko container"""
        return self.apko().container()

    @function
    def config(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
    ) -> Config:
        """Returns the derived Apko config"""
        return Config(workdir=self.workdir, config=config, apko=self.apko())

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
    async def build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        tag: Annotated[str | None, Doc("Image tag")] = "apko-build",
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = None,
        keyring_append: Annotated[
            dagger.File | None, Doc("Path to extra keys to include in the keyring")
        ] = None,
        repository_append: Annotated[
            dagger.Directory | None, Doc("Path to extra repositories to include")
        ] = None,
    ) -> Build:
        """Build an image using Apko"""
        apko = (
            self.apko()
            .container()
            .with_mounted_file(
                path="$APKO_CONFIG_FILE",
                source=config,
                owner=self.user,
                expand=True,
            )
        )

        cmd = [
            "build",
            "$APKO_CONFIG_FILE",
            tag,
            "$APKO_IMAGE_TARBALL",
            "--cache-dir",
            "$APKO_CACHE_DIR",
            "--sbom-path",
            "$APKO_SBOM_DIR",
        ]

        if keyring_append:
            apko = apko.with_mounted_file(
                "$APKO_KEYRING_FILE",
                source=keyring_append,
                owner=self.user,
                expand=True,
            )
            cmd.extend(["--keyring-append", "$APKO_KEYRING_FILE"])

        if repository_append:
            apko = apko.with_mounted_directory(
                "$APKO_REPOSITORY_DIR",
                source=repository_append,
                owner=self.user,
                expand=True,
            )
            cmd.extend(["--repository-append", "$APKO_REPOSITORY_DIR"])

        platforms = platforms or [await dag.default_platform()]
        for platform in platforms:
            cmd.extend(["--arch", platform.split("/")[1]])

        apko = await apko.with_exec(cmd, use_entrypoint=True, expand=True)
        tarball = apko.file("$APKO_IMAGE_TARBALL", expand=True)
        current_platform: dagger.Platform = await self.container_.platform()
        platform_variants: list[dagger.Container] = []
        for platform in platforms:
            if platform == current_platform:
                self.container_ = self.container_.import_(tarball)
            else:
                platform_variants.append(
                    dag.container(platform=platform).import_(tarball)
                )

        return Build(
            container_=self.container_,
            platform_variants=platform_variants,
            sbom_=Sbom(directory_=apko.directory("$APKO_SBOM_DIR", expand=True)),
            apko=self.apko(),
        )

    @function
    async def publish(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")],
        sbom: Annotated[bool | None, Doc("generate SBOM")] = True,
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = None,
        local: Annotated[
            bool | None, Doc("Publish image just to local Docker daemon")
        ] = False,
        keyring_append: Annotated[
            dagger.File | None, Doc("Path to extra keys to include in the keyring")
        ] = None,
        repository_append: Annotated[
            dagger.Directory | None, Doc("Path to extra repositories to include")
        ] = None,
        force: Annotated[
            bool | None, Doc("Force image publishing (invalidate cache)")
        ] = False,
    ) -> Image:
        """Publish an image using Apko"""
        apko = (
            self.apko()
            .container()
            .with_mounted_file(
                path="$APKO_CONFIG_FILE",
                source=config,
                owner=self.user,
                expand=True,
            )
        )

        if force:
            # Cache buster
            apko = apko.with_env_variable("CACHEBUSTER", str(datetime.now()))

        cmd = ["publish", "$APKO_CONFIG_FILE"]

        cmd.extend(tags)
        cmd.extend(["--cache-dir", "$APKO_CACHE_DIR"])

        if keyring_append:
            apko = apko.with_mounted_file(
                "$APKO_KEYRING_FILE",
                source=keyring_append,
                owner=self.user,
                expand=True,
            )
            cmd.extend(["--keyring-append", "$APKO_KEYRING_FILE"])

        if repository_append:
            apko = apko.with_mounted_directory(
                "$APKO_REPOSITORY_DIR",
                source=repository_append,
                owner=self.user,
                expand=True,
            )
            cmd.extend(["--repository-append", "$APKO_REPOSITORY_DIR"])

        if sbom:
            cmd.extend(["--sbom=true", "--sbom-path", "$APKO_SBOM_DIR"])
        else:
            cmd.append("--sbom=false")

        platforms = platforms or [await dag.default_platform()]
        for platform in platforms:
            cmd.extend(["--arch", platform.split("/")[1]])

        if local:
            cmd.append("--local")

        # Publish the container
        apko = apko.with_exec(cmd, use_entrypoint=True, expand=True)
        # Retrieves the published container
        container: dagger.Container = self.container_.from_(tags[0])

        return Image(
            address=await container.image_ref(),
            container_=container,
            sbom_=Sbom(directory_=apko.directory("$APKO_SBOM_DIR", expand=True)),
            apko=self.apko(),
        )
