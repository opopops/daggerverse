from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, field, object_type


@object_type
class Cosign:
    """Cosign CLI"""

    image: Annotated[str, Doc("Cosign image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    version: Annotated[str, Doc("Cosign version")] | None = field(default=None)
    user: Annotated[str, Doc("Cosign image user")] = field(default="65532")

    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )

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
        pkg = "cosign"
        if self.version:
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
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
        image: Annotated[str, Doc("Image digest URI")],
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")] | None = None,
        password: Annotated[dagger.Secret, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[str, Doc("OIDC provider to be used to issue ID toke")]
        | None = None,
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = False,
    ) -> str:
        """Sign image with Cosign"""
        container = self.container()
        cmd = ["sign", image]

        if private_key:
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
            container = container.with_secret_variable(
                "COSIGN_PASSWORD", password
            ).with_secret_variable("COSIGN_PRIVATE_KEY", private_key)

        if oidc_provider:
            cmd.extend(["--oidc-provider", oidc_provider])

        if oidc_issuer:
            cmd.extend(["--oidc-issuer", oidc_issuer])

        if recursive:
            cmd.append("--recursive")

        container = container.with_env_variable("COSIGN_YES", "true").with_exec(
            cmd, use_entrypoint=True, expand=True
        )

        return await container.stdout()

    @function
    async def with_sign(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")] | None = None,
        password: Annotated[dagger.Secret, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[str, Doc("OIDC provider to be used to issue ID toke")]
        | None = None,
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = False,
    ) -> Self:
        """Sign image with Cosign (For chaining)"""
        await self.sign(
            image=image,
            private_key=private_key,
            password=password,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )
        return self

    @function
    async def attest(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        predicate: Annotated[dagger.File, Doc("path to the predicate file")],
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")] | None = None,
        password: Annotated[dagger.Secret, Doc("Cosign password")] | None = None,
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")]
        | None = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[str, Doc("OIDC provider to be used to issue ID toke")]
        | None = None,
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = False,
    ) -> str:
        """Attest image with Cosign"""
        predicate_name = await predicate.name()

        container = self.container().with_mounted_file(
            path=f"/tmp/{predicate_name}",
            source=predicate,
            owner=self.user,
            expand=True,
        )

        cmd = ["attest", image]

        if private_key:
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
            container = container.with_secret_variable(
                "COSIGN_PASSWORD", password
            ).with_secret_variable("COSIGN_PRIVATE_KEY", private_key)

        if type_:
            cmd.extend(["--type", type_])

        if predicate:
            cmd.extend(["--predicate", f"/tmp/{predicate_name}"])

        if oidc_provider:
            cmd.extend(["--oidc-provider", oidc_provider])

        if oidc_issuer:
            cmd.extend(["--oidc-issuer", oidc_issuer])

        if recursive:
            cmd.append("--recursive")

        container = container.with_env_variable("COSIGN_YES", "true").with_exec(
            cmd, use_entrypoint=True, expand=True
        )

        return await container.stdout()

    @function
    async def with_attest(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        predicate: Annotated[dagger.File, Doc("path to the predicate file")],
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")] | None = None,
        password: Annotated[dagger.Secret, Doc("Cosign password")] | None = None,
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")]
        | None = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[str, Doc("OIDC provider to be used to issue ID toke")]
        | None = None,
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = False,
    ) -> Self:
        """Attest image with Cosign (For chaining)"""
        await self.attest(
            image=image,
            private_key=private_key,
            password=password,
            type_=type_,
            predicate=predicate,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )
        return self
