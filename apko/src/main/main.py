from typing import Annotated, Self
import os
import dataclasses
import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .build import Build
from .image import Image


@object_type
class Apko:
    """Apko module"""

    image: Annotated[str, Doc("wolfi-base image")] = (
        "cgr.dev/chainguard/wolfi-base:latest"
    )
    version: Annotated[str, Doc("Apko version")] = "latest"
    user: Annotated[str, Doc("Image user")] = "65532"
    apko_: dagger.Container | None = None

    container_: dagger.Container = dataclasses.field(
        default_factory=lambda: dag.container()
    )

    @function(name="container")
    def apko(self) -> dagger.Container:
        """Returns the apko container"""
        if self.apko_:
            return self.apko_

        container: dagger.Container = dag.container()

        pkg = "apko"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.apko_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_entrypoint(["/usr/bin/apko"])
            .with_user(self.user)
            .with_env_variable("APKO_CACHE_DIR", "/tmp/cache")
            .with_env_variable("APKO_CONFIG_DIR", "/tmp/config")
            .with_env_variable("APKO_WORK_DIR", "/tmp/work")
            .with_env_variable("APKO_OUTPUT_DIR", "/tmp/output")
            .with_env_variable("APKO_SBOM_DIR", "/tmp/sbom")
            .with_env_variable(
                "APKO_OUTPUT_TAR", "${APKO_OUTPUT_DIR}/image.tar", expand=True
            )
            .with_env_variable(
                "APKO_KEYRING_FILE", "/tmp/keyring/melange.rsa.pub", expand=True
            )
            .with_env_variable("APKO_REPOSITORY_DIR", "/tmp/repository", expand=True)
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker", expand=True)
            .with_mounted_cache(
                "$APKO_CACHE_DIR",
                dag.cache_volume("apko-cache"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
                expand=True,
            )
            .with_exec(
                ["mkdir", "-p", "$APKO_OUTPUT_DIR", "$APKO_SBOM_DIR", "$DOCKER_CONFIG"],
                use_entrypoint=False,
                expand=True,
            )
            .with_new_file(
                "${DOCKER_CONFIG}/config.json",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
        )
        return self.apko_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        container: dagger.Container = self.apko()
        cmd = [
            "sh",
            "-c",
            (
                f"apko login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.apko_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    @function
    async def build(
        self,
        workdir: Annotated[
            dagger.Directory, DefaultPath("/"), Doc("Working dir"), Name("context")
        ],
        config: Annotated[dagger.File, Doc("Config file")],
        tag: Annotated[str, Doc("Image tag")],
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
        config_name = await config.name()

        apko = (
            self.apko()
            .with_mounted_file(
                path=os.path.join("$APKO_CONFIG_DIR", config_name),
                source=config,
                owner=self.user,
                expand=True,
            )
            .with_mounted_directory(
                path="$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )
            .with_workdir("$APKO_WORK_DIR", expand=True)
        )

        cmd = [
            "build",
            os.path.join("$APKO_CONFIG_DIR", config_name),
            tag,
            "${APKO_OUTPUT_DIR}/image.tar",
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
        tarball = apko.directory("$APKO_OUTPUT_DIR", expand=True).file("image.tar")

        platform_variants: list[dagger.Container] = []
        for platform in platforms:
            platform_variants.append(dag.container(platform=platform).import_(tarball))

        return Build(platform_variants=platform_variants, tag=tag, apko=apko)

    @function
    async def publish(
        self,
        workdir: Annotated[
            dagger.Directory, DefaultPath("/"), Doc("Working dir"), Name("context")
        ],
        config: Annotated[dagger.File, Doc("Config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")],
        sbom: Annotated[bool, Doc("generate an SBOM")] = True,
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = None,
        local: Annotated[
            bool, Doc("Publish image just to local Docker daemon")
        ] = False,
        keyring_append: Annotated[
            dagger.File | None, Doc("Path to extra keys to include in the keyring")
        ] = None,
        repository_append: Annotated[
            dagger.Directory | None, Doc("Path to extra repositories to include")
        ] = None,
    ) -> Image:
        """Publish an image using Apko"""
        config_name = await config.name()

        apko = (
            self.apko()
            .with_mounted_file(
                path=os.path.join("$APKO_CONFIG_DIR", config_name),
                source=config,
                owner=self.user,
                expand=True,
            )
            .with_mounted_directory(
                path="$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )
            .with_workdir("$APKO_WORK_DIR", expand=True)
        )

        cmd = ["publish", os.path.join("$APKO_CONFIG_DIR", config_name)]

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

        apko = await apko.with_exec(cmd, use_entrypoint=True, expand=True)
        return Image(address=tags[0], apko=apko)
