from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, object_type


@object_type
class Cosign:
    """Cosign CLI"""

    image: str
    version: str
    user: str
    docker_config: dagger.File | None
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        image: Annotated[str, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str, Doc("Cosign version")] = "latest",
        user: Annotated[str, Doc("Image user")] = "65532",
        docker_config: Annotated[dagger.File | None, Doc("Docker config file")] = None,
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            docker_config=docker_config,
            container_=None,
        )

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        pkg = "cosign"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_entrypoint(["/usr/bin/cosign"])
            .with_user(self.user)
            .with_exec(
                ["mkdir", "-p", "$DOCKER_CONFIG"],
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

        if self.docker_config:
            self.container_ = self.container_.with_file(
                "${DOCKER_CONFIG}/config.json",
                source=self.docker_config,
                owner=self.user,
                permissions=0o600,
                expand=True,
            )

        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
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
    async def generate_key_pair(
        self, password: Annotated[dagger.Secret | None, Doc("Key password")] = None
    ) -> dagger.Directory:
        """Generate key pair"""
        cosign_password: str = await password.plaintext() if password else ""
        container = (
            self.container()
            .with_env_variable("COSIGN_PASSWORD", cosign_password)
            .with_workdir("/tmp/cosign")
            .with_exec(["generate-key-pair"], use_entrypoint=True)
        )
        return container.directory("/tmp/cosign")

    @function
    async def sign(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
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
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
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
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")] = "",
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
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
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")] = "",
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
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

    @function
    async def copy(
        self,
        source: Annotated[str, Doc("Source image")],
        destination: Annotated[str, Doc("Destination image")],
        platform: Annotated[
            dagger.Platform | None,
            Doc(
                "Only copy container image and its signatures for a specific platform image"
            ),
        ] = None,
        only: Annotated[
            list[str],
            Doc(
                "Custom string array to only copy specific items. ex: --only=sig,att,sbom"
            ),
        ] = (),
        force: Annotated[
            bool,
            Doc("Overwrite destination image(s), if necessary"),
        ] = False,
        allow_http_registry: Annotated[
            bool,
            Doc("Whether to allow using HTTP protocol while connecting to registries"),
        ] = False,
        allow_insecure_registry: Annotated[
            bool, Doc("whether to allow insecure connections to registries")
        ] = False,
    ) -> str:
        """Copy the supplied container image and signatures"""
        container = self.container()
        cmd = ["copy", source, destination]
        if platform:
            cmd.extend(["--platform", platform])
        if only:
            cmd.extend(["--only", ",".join(only)])
        if force:
            cmd.append("--force")
        if allow_http_registry:
            cmd.append("--allow-http-registry")
        if allow_insecure_registry:
            cmd.append("--allow-insecure-registry")
        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def with_copy(
        self,
        source: Annotated[str, Doc("Source image")],
        destination: Annotated[str, Doc("Destination image")],
        platform: Annotated[
            dagger.Platform | None,
            Doc(
                "Only copy container image and its signatures for a specific platform image"
            ),
        ] = None,
        only: Annotated[
            list[str],
            Doc(
                "Custom string array to only copy specific items. ex: --only=sig,att,sbom"
            ),
        ] = (),
        force: Annotated[
            bool,
            Doc("Overwrite destination image(s), if necessary"),
        ] = False,
        allow_http_registry: Annotated[
            bool,
            Doc("Whether to allow using HTTP protocol while connecting to registries"),
        ] = False,
        allow_insecure_registry: Annotated[
            bool, Doc("whether to allow insecure connections to registries")
        ] = False,
    ) -> Self:
        """Copy the supplied container image and signatures (for chaining)"""
        await self.copy(
            source=source,
            destination=destination,
            platform=platform,
            only=only,
            force=force,
            allow_http_registry=allow_http_registry,
            allow_insecure_registry=allow_insecure_registry,
        )
        return self
