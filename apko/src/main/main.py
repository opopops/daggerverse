from typing import Annotated, Self
from urllib.parse import urlparse
import os
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

    container_: dagger.Container | None = None

    def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{self.image}")
        return url.netloc

    def docker_config(self) -> dagger.File:
        """Returns the docker config file"""
        return self.container().file("${DOCKER_CONFIG}/config.json", expand=True)

    @function
    def container(self) -> dagger.Container:
        """Returns apko container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()

        pkg = "apko"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
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
        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        container: dagger.Container = self.container()
        cmd = [
            "sh",
            "-c",
            (
                f"apko login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    @function
    async def build(
        self,
        workdir: Annotated[
            dagger.Directory, DefaultPath("."), Doc("Working dir"), Name("context")
        ],
        config: Annotated[dagger.File, Doc("Config file")],
        tag: Annotated[str, Doc("Image tag")],
        arch: Annotated[str, Doc("Architectures to build for")] = "",
        format_: Annotated[str, Doc("Image format"), Name("format")] = "oci",
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
            self.container()
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

        output: str = "${APKO_OUTPUT_DIR}"
        if format_ == "tarball":
            output = "${APKO_OUTPUT_DIR}/image.tar"
        cmd = [
            "build",
            os.path.join("$APKO_CONFIG_DIR", config_name),
            tag,
            output,
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

        if arch:
            cmd.extend(["--arch", arch])

        if format_ == "tarball":
            return Build(
                tarball=apko.with_exec(cmd, use_entrypoint=True, expand=True)
                .directory("$APKO_OUTPUT_DIR", expand=True)
                .file("image.tar"),
                sbom=apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
                    "$APKO_SBOM_DIR", expand=True
                ),
                tag=tag,
                docker_config=self.docker_config(),
            )
        return Build(
            oci=apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
                "$APKO_OUTPUT_DIR", expand=True
            ),
            sbom=apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
                "$APKO_SBOM_DIR", expand=True
            ),
            tag=tag,
            docker_config=self.docker_config(),
        )

    @function
    async def publish(
        self,
        workdir: Annotated[
            dagger.Directory, DefaultPath("."), Doc("Working dir"), Name("context")
        ],
        config: Annotated[dagger.File, Doc("Config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")],
        sbom: Annotated[bool, Doc("generate an SBOM")] = True,
        arch: Annotated[str, Doc("Architectures to build for")] = "",
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
            self.container()
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

        if arch:
            cmd.extend(["--arch", arch])

        if local:
            cmd.append("--local")

        await apko.with_exec(cmd, use_entrypoint=True, expand=True)
        return Image(
            address=tags[0],
            sbom=apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
                "$APKO_SBOM_DIR", expand=True
            ),
            docker_config=self.docker_config(),
        )
