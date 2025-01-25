from typing import Annotated, Self

import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Cosign:
    """Cosign CLI"""

    image: Annotated[str, Doc("Cosign image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("Cosign image user")] = field(default="65532")

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "cosign"])
            .with_entrypoint(["/usr/bin/cosign"])
            .with_user(self.user)
        )

        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] | None = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.container()
        cmd = [
            "sh",
            "-c",
            (
                f"cosign login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    @function
    async def sign(
        self,
        digest: Annotated[str, Doc("Image digest")],
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")],
        password: Annotated[dagger.Secret, Doc("Cosign password")],
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = False,
        docker_config: Annotated[dagger.Directory, Doc("Docker config directory")]
        | None = None,
        registry_username: Annotated[str, Doc("Registry username")] | None = None,
        registry_password: (
            Annotated[dagger.Secret, Doc("Registry password")] | None
        ) = None,
    ) -> str:
        """Sign image with Cosign"""
        container = self.container()
        cmd = ["sign", digest, "--key", "env://COSIGN_PRIVATE_KEY"]

        if recursive:
            cmd.append("--recursive")

        if registry_username and registry_password:
            container = container.with_registry_auth(
                address=self.image, username=registry_username, secret=registry_password
            )

        if docker_config:
            container = container.with_env_variable(
                "DOCKER_CONFIG", "/tmp/docker"
            ).with_mounted_directory("/tmp/docker", docker_config, owner=self.user)

        container = (
            container.with_env_variable("COSIGN_YES", "true")
            .with_secret_variable("COSIGN_PASSWORD", password)
            .with_secret_variable("COSIGN_PRIVATE_KEY", private_key)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()
