from typing import Annotated, Self
import os
import dagger
from dagger import Doc, Name, dag, function, field, object_type

from .build import Build as Build


@object_type
class Apko:
    """Apko module"""

    image: Annotated[str, Doc("Apko image")] = field(
        default="cgr.dev/chainguard/apko:latest"
    )
    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container: Annotated[dagger.Container, Doc("Apko container")] | None = field(
        default=None
    )

    def container_(self) -> dagger.Container:
        """Returns configured apko container"""
        if self.container:
            return self.container

        container: dagger.Container = dag.container()
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        self.container = (
            container.from_(address=self.image)
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
        )
        return self.container

    @function
    async def with_registry_auth(
        self,
        address: Annotated[str, Doc("Registry host")] | None = "index.docker.io",
        username: Annotated[str, Doc("Registry username")] | None = None,
        secret: Annotated[dagger.Secret, Doc("Registry password")] | None = None,
        docker_config: Annotated[dagger.Directory, Doc("Docker config directory")]
        | None = None,
    ) -> Self:
        """Authenticates with registry"""
        container: dagger.Container = self.container_()
        if docker_config:
            self.container = container.with_env_variable(
                "DOCKER_CONFIG", "/tmp/docker"
            ).with_mounted_directory("/tmp/docker", docker_config, owner=self.user)
        else:
            cmd = [
                "login",
                address,
                "--username",
                username,
                "--password",
                # TODO: use $password instead once dagger is fixed
                await secret.plaintext(),
            ]
            self.container = container.with_secret_variable(
                "password", secret
            ).with_exec(cmd, use_entrypoint=True, expand=True)
        return self

    @function
    async def build(
        self,
        tag: Annotated[str, Doc("Image tag")],
        workdir: Annotated[dagger.Directory, Doc("Working dir"), Name("context")],
        arch: Annotated[str, Doc("Architectures to build for")] | None,
        config: Annotated[str, Doc("Config file")] | None = "apko.yaml",
    ) -> Build:
        """Build an image using Apko"""
        apko = (
            self.container_()
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
            registry_username=self.username,
            registry_password=self.password,
        )

    @function
    async def publish(
        self,
        tag: Annotated[str, Doc("Image tag")],
        workdir: Annotated[dagger.Directory, Doc("Working dir"), Name("context")],
        arch: Annotated[str, Doc("Architectures to build for")] | None,
        config: Annotated[str, Doc("Config file")] | None = "apko.yaml",
    ) -> dagger.Directory:
        """Publish an image using Apko"""
        apko = (
            self.container_()
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
            "--sbom-path",
            "$APKO_OUTPUT_DIR",
        ]

        if arch:
            cmd.extend(["--arch", arch])

        return apko.with_exec(cmd, use_entrypoint=True, expand=True).directory(
            "$APKO_OUTPUT_DIR", expand=True
        )
