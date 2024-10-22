from typing import Annotated

import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Cosign:
    """Cosign CLI"""

    image: Annotated[str, Doc("Cosign image")] = field(
        default="cgr.dev/chainguard/cosign:latest"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("Cosign image user")] = field(default="nonroot")

    def container(self) -> dagger.Container:
        """Returns Cosign container"""
        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        return container.from_(address=self.image).with_user(self.user)

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

        cmd = ["sign", digest, "--key", "env://COSIGN_PRIVATE_KEY"]

        if recursive:
            cmd.append("--recursive")

        if registry_username and registry_password:
            cmd.extend(
                [
                    "--registry-username",
                    registry_username,
                    "--registry-password",
                    await registry_password.plaintext(),
                ]
            )

        container = self.container()

        if docker_config:
            container = container.with_env_variable(
                "DOCKER_CONFIG", "/tmp/docker"
            ).with_mounted_directory("/tmp/docker", docker_config, owner=self.user)

        container = (
            container.with_env_variable("COSIGN_YES", "true")
            .with_secret_variable("COSIGN_PASSWORD", password)
            .with_secret_variable("COSIGN_PRIVATE_KEY", private_key)
            .with_exec(cmd, use_entrypoint=True)
        )

        return await container.stdout()
