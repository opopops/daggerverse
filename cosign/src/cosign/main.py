from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, object_type


@object_type
class Cosign:
    """Cosign Module"""

    image: str
    version: str
    user: str
    container_: dagger.Container | None

    private_key_: dagger.Secret | None = None
    public_key_: dagger.File | None = None
    password_: dagger.Secret | None = None

    oidc_provider_: str | None = None
    oidc_issuer_: str | None = None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Cosign version")] = "latest",
        user: Annotated[str | None, Doc("Image user")] = "65532",
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
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
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_env_variable("COSIGN_PASSWORD", "")
            .with_env_variable("COSIGN_WORK_DIR", "/cosign")
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_user(self.user)
            .with_exec(["mkdir", "-p", "$DOCKER_CONFIG"], expand=True)
            .with_new_file(
                "${DOCKER_CONFIG}/config.json",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
            .with_workdir("$COSIGN_WORK_DIR", expand=True)
            .with_entrypoint(["/usr/bin/cosign"])
        )

        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
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
    def docker_config(self) -> dagger.File:
        """Returns the Docker config file"""
        return self.container().file("${DOCKER_CONFIG}/config.json", expand=True)

    @function
    def with_docker_config(
        self, docker_config: Annotated[dagger.File, Doc("Docker config file")]
    ) -> Self:
        """Set Docker config file (for chaining)"""
        self.container_ = self.container().with_file(
            "${DOCKER_CONFIG}/config.json",
            source=docker_config,
            owner=self.user,
            permissions=0o600,
            expand=True,
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
        self.container_ = self.container().with_env_variable(
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
        self.container_ = self.container().with_secret_variable(
            name=name, secret=secret
        )
        return self

    @function
    def generate_key_pair(
        self,
        password: Annotated[dagger.Secret | None, Doc("Key password")] = dag.set_secret(
            "cosign-password", ""
        ),
    ) -> dagger.Directory:
        """Generate key pair"""
        container = (
            self.container()
            .with_secret_variable("COSIGN_PASSWORD", password)
            .with_exec(["generate-key-pair"], use_entrypoint=True)
        )
        return container.directory(".")

    @function
    async def with_generate_key_pair(
        self,
        password: Annotated[dagger.Secret | None, Doc("Key password")] = dag.set_secret(
            "cosign-password", ""
        ),
    ) -> Self:
        """Generate and include a new key pair (for chaining)"""
        keys: dagger.Directory = self.generate_key_pair(password=password)
        self.with_private_key(
            key=dag.set_secret("cosign-key", await keys.file("cosign.key").contents()),
            password=password,
            public_key=await keys.file("cosign.pub"),
        )
        return self

    @function
    def with_private_key(
        self,
        key: Annotated[dagger.Secret, Doc("Key to use for signing")],
        password: Annotated[dagger.Secret | None, Doc("Key password")] = dag.set_secret(
            "cosign-password", ""
        ),
        public_key: Annotated[
            dagger.File | None, Doc("Public key to use for verification")
        ] = None,
    ) -> Self:
        """Include the specified private key (for chaining)"""
        self.password_ = password
        self.private_key_ = key
        self.public_key_ = public_key
        self.container_ = (
            self.container()
            .with_secret_variable("COSIGN_PRIVATE_KEY", key)
            .with_secret_variable("COSIGN_PASSWORD", password)
        )
        return self

    @function
    def with_oidc(
        self,
        provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID token")
        ] = "",
    ) -> Self:
        """Set OIDC provider and issuer (for chaining)"""
        self.oidc_provider_ = provider
        self.oidc_issuer_ = issuer
        return self

    @function
    async def clean(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        type_: Annotated[str | None, Doc("Type of clean")] = "all",
    ) -> str:
        """Remove all signatures from an image"""
        return (
            await self.container()
            .with_exec(
                ["clean", image, "--force", "--type", type_], use_entrypoint=True
            )
            .stdout()
        )

    @function
    async def with_clean(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        type_: Annotated[str | None, Doc("Type of clean")] = "all",
    ) -> Self:
        """Remove all signatures from an image (for chaining)"""
        await self.clean(image=image, type_=type_)
        return self

    @function
    async def sign(
        self,
        image: Annotated[str, Doc("Image digest URI")],
        annotations: Annotated[
            list[str] | None, Doc("Extra key=value pairs to sign")
        ] = (),
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        identity_token: Annotated[
            dagger.Secret | None, Doc("Cosign identity token")
        ] = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
    ) -> str:
        """Sign image with Cosign"""
        container = self.container()
        cmd = ["sign", image]

        for annotation in annotations:
            cmd.extend(["--annotations", annotation])

        if private_key or self.private_key_:
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
            container = container.with_secret_variable(
                "COSIGN_PRIVATE_KEY", private_key
            )

        if password or self.password_:
            container = container.with_secret_variable(
                "COSIGN_PASSWORD", password or self.password_
            )

        if oidc_provider or self.oidc_provider_:
            cmd.extend(["--oidc-provider", oidc_provider or self.oidc_provider_])

        if oidc_issuer or self.oidc_issuer_:
            cmd.extend(["--oidc-issuer", oidc_issuer or self.oidc_issuer_])

        if identity_token:
            cmd.extend(["--identity-token", await identity_token.plaintext()])

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
        annotations: Annotated[
            list[str] | None, Doc("Extra key=value pairs to sign")
        ] = (),
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        identity_token: Annotated[
            dagger.Secret | None, Doc("Cosign identity token")
        ] = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
    ) -> Self:
        """Sign image with Cosign (For chaining)"""
        await self.sign(
            image=image,
            annotations=annotations,
            private_key=private_key,
            password=password,
            identity_token=identity_token,
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
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")],
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[
            dagger.Secret | None, Doc("Cosign password")
        ] = dag.set_secret("cosign_password", ""),
        identity_token: Annotated[
            dagger.Secret | None, Doc("Cosign identity token")
        ] = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool | None,
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

        if private_key or self.private_key_:
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
            container = container.with_secret_variable(
                "COSIGN_PRIVATE_KEY", private_key
            )

        if password or self.password_:
            container = container.with_secret_variable(
                "COSIGN_PASSWORD", password or self.password_
            )

        if oidc_provider or self.oidc_provider_:
            cmd.extend(["--oidc-provider", oidc_provider or self.oidc_provider_])

        if oidc_issuer or self.oidc_issuer_:
            cmd.extend(["--oidc-issuer", oidc_issuer or self.oidc_issuer_])

        if identity_token:
            cmd.extend(["--identity-token", await identity_token.plaintext()])

        if type_:
            cmd.extend(["--type", type_])

        if predicate:
            cmd.extend(["--predicate", f"/tmp/{predicate_name}"])

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
        type_: Annotated[str, Doc("Specify a predicate type"), Name("type")],
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
        identity_token: Annotated[
            dagger.Secret | None, Doc("Cosign identity token")
        ] = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ] = "",
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
    ) -> Self:
        """Attest image with Cosign (For chaining)"""
        await self.attest(
            image=image,
            predicate=predicate,
            type_=type_,
            private_key=private_key,
            password=password,
            identity_token=identity_token,
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
            list[str] | None,
            Doc(
                "Custom string array to only copy specific items. ex: --only=sig,att,sbom"
            ),
        ] = (),
        force: Annotated[
            bool | None,
            Doc("Overwrite destination image(s), if necessary"),
        ] = False,
        allow_http_registry: Annotated[
            bool | None,
            Doc("Whether to allow using HTTP protocol while connecting to registries"),
        ] = False,
        allow_insecure_registry: Annotated[
            bool | None, Doc("whether to allow insecure connections to registries")
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
            list[str] | None,
            Doc(
                "Custom string array to only copy specific items. ex: --only=sig,att,sbom"
            ),
        ] = (),
        force: Annotated[
            bool | None,
            Doc("Overwrite destination image(s), if necessary"),
        ] = False,
        allow_http_registry: Annotated[
            bool | None,
            Doc("Whether to allow using HTTP protocol while connecting to registries"),
        ] = False,
        allow_insecure_registry: Annotated[
            bool | None, Doc("whether to allow insecure connections to registries")
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
