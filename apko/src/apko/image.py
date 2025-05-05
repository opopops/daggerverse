import json
from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, dag, field, function, object_type


@object_type
class Image:
    """Apko Image"""

    address: str = field()
    apko_: dagger.Container
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        address: Annotated[str, Doc("Image address")],
        apko: Annotated[dagger.Container, Doc("Apko container")],
        container: Annotated[dagger.Container | None, Doc("Image container")] = None,
    ):
        """Constructor"""
        if container is None:
            container = dag.container().from_(address)
        return cls(address=address, apko_=apko, container_=container)

    def docker_config(self) -> dagger.File:
        """Returns the docker config file"""
        return self.apko().file("${DOCKER_CONFIG}/config.json", expand=True)

    def crane(self) -> dagger.Crane:
        """Returns crane"""
        return dag.crane(docker_config=self.docker_config())

    def cosign(self) -> dagger.Cosign:
        """Returns cosign"""
        return dag.cosign(docker_config=self.docker_config())

    def grype(self) -> dagger.Grype:
        """Returns grype"""
        return dag.grype(docker_config=self.docker_config())

    @function
    def apko(self) -> dagger.Container:
        """Returns the apko container"""
        return self.apko_

    @function
    def container(self) -> dagger.Container:
        """Returns the image container"""
        return self.container_

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the image tarball"""
        return self.container().as_tarball()

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        self.container_ = self.container().with_registry_auth(
            address=address, username=username, secret=secret
        )
        cmd = [
            "sh",
            "-c",
            (
                f"apko login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.apko_ = (
            self.apko()
            .with_secret_variable("REGISTRY_PASSWORD", secret)
            .with_exec(cmd, use_entrypoint=False)
        )
        return self

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.apko().directory("$APKO_SBOM_DIR", expand=True)

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves image platforms"""
        platforms: list[dagger.Platform] = []
        crane = self.crane()

        manifest = json.loads(await crane.manifest(image=self.address))

        for entry in manifest.get("manifests", []):
            platform = entry["platform"]
            architecture = platform["architecture"]
            os = platform["os"]
            platforms.append(dagger.Platform(f"{os}/{architecture}"))
        return platforms

    @function
    async def ref(self) -> str:
        """Retrieves the fully qualified image ref"""
        ref = await self.crane().digest(image=self.address, full_ref=True)
        return ref.strip()

    @function
    async def digest(self) -> str:
        """Retrieves the image digest"""
        digest = await self.crane().digest(image=self.address)
        return digest.strip()

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        result = await self.crane().tag(image=self.address, tag=tag)
        return result

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
        return self

    @function
    async def copy(self, target: Annotated[str, Doc("Target")]) -> str:
        """Copy image to another registry"""
        result = await self.crane().copy(source=self.address, target=target)
        return result

    @function
    async def with_copy(self, target: Annotated[str, Doc("Target")]) -> Self:
        """Copy image to another registry (for chaining)"""
        await self.copy(target=target)
        return self

    @function
    def scan(
        self,
        severity_cutoff: (
            Annotated[
                str,
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan image using Grype"""
        grype = self.grype()
        return grype.scan_image(
            source=self.address,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )

    @function
    def with_scan(
        self,
        severity_cutoff: (
            Annotated[
                str,
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan image using Grype (for chaining)"""
        self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        return self

    @function
    async def sign(
        self,
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
        ] = True,
    ) -> str:
        """Sign image with Cosign"""
        return await self.cosign().sign(
            image=await self.ref(),
            private_key=private_key,
            password=password,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )

    @function
    async def with_sign(
        self,
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
        ] = True,
    ) -> Self:
        """Sign image with Cosign (for chaining)"""
        await self.sign(
            private_key=private_key,
            password=password,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )
        return self
