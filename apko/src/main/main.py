from typing import Annotated, Self
import os
import dagger
from dagger import Doc, Name, dag, function, field, object_type

from .build import Build
from .image import Image


@object_type
class Apko:
    """Apko module"""

    image: Annotated[str, Doc("Base image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container_: dagger.Container | None = None

    def container(self) -> dagger.Container:
        """Returns configured apko container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "apko"])
            .with_entrypoint(["/usr/bin/apko"])
            .with_user(self.user)
            .with_env_variable("APKO_CACHE_DIR", "/tmp/cache", expand=True)
            .with_env_variable("APKO_WORK_DIR", "/tmp/work", expand=True)
            .with_env_variable("APKO_OUTPUT_DIR", "/tmp", expand=True)
            .with_env_variable(
                "APKO_OUTPUT_TAR", "${APKO_OUTPUT_DIR}/image.tar", expand=True
            )
            .with_mounted_cache(
                "$APKO_CACHE_DIR",
                dag.cache_volume("APKO_CACHE"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
                expand=True,
            )
            .with_mounted_cache(
                "/.docker",
                dag.cache_volume("APKO_DOCKER_CONFIG"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
            )
        )
        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] | None = "docker.io",
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
    def build(
        self,
        tag: Annotated[str, Doc("Image tag")],
        workdir: Annotated[dagger.Directory, Doc("Working dir"), Name("context")],
        config: Annotated[str, Doc("Config file")] = "apko.yaml",
        arch: Annotated[str, Doc("Architectures to build for")] | None = None,
    ) -> Build:
        """Build an image using Apko"""
        apko = (
            self.container()
            .with_mounted_directory(
                path="$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )
            .with_workdir(f"$APKO_WORK_DIR/{os.path.dirname(config)}", expand=True)
        )

        cmd = [
            "build",
            os.path.basename(config),
            tag,
            "$APKO_OUTPUT_DIR",
            "--cache-dir",
            "$APKO_CACHE_DIR",
            "--sbom-path",
            "$APKO_OUTPUT_DIR",
        ]

        if arch:
            cmd.extend(["--arch", arch])

        return Build(
            directory=apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
                "$APKO_OUTPUT_DIR", expand=True
            ),
            registry=self.registry,
            username=self.username,
            password=self.password,
        )

    @function
    async def publish(
        self,
        tag: Annotated[str, Doc("Image tag")],
        workdir: Annotated[dagger.Directory, Doc("Working dir"), Name("context")],
        config: Annotated[str, Doc("Config file")] = "apko.yaml",
        sbom: Annotated[bool, Doc("generate an SBOM")] | None = True,
        arch: Annotated[str, Doc("Architectures to build for")] | None = None,
    ) -> Image:
        """Publish an image using Apko"""
        apko = (
            self.container()
            .with_mounted_directory(
                path="$APKO_WORK_DIR", source=workdir, owner=self.user, expand=True
            )
            .with_workdir(f"$APKO_WORK_DIR/{os.path.dirname(config)}", expand=True)
        )

        cmd = [
            "publish",
            os.path.basename(config),
            tag,
            "--cache-dir",
            "$APKO_CACHE_DIR",
        ]

        if sbom:
            cmd.extend(["--sbom=true", "--sbom-path", "$APKO_OUTPUT_DIR"])
        else:
            cmd.append("--sbom=false")

        if arch:
            cmd.extend(["--arch", arch])

        await apko.with_exec(cmd, use_entrypoint=True, expand=True)
        return Image(address=tag, username=self.username, password=self.password)
