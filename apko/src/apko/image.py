import json
from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Image:
    """Apko Image"""

    address_: str
    apko_: dagger.Container
    container_: dagger.Container | None
    sbom_: dagger.Directory | None

    @classmethod
    async def create(
        cls,
        address: Annotated[str, Doc("Image address")],
        apko: Annotated[dagger.Container, Doc("Apko container")],
        container: Annotated[dagger.Container | None, Doc("Image container")] = None,
        sbom: Annotated[dagger.Directory | None, Doc("Image SBOMs directory")] = None,
    ):
        """Constructor"""
        if container is None:
            container = dag.container()
        return cls(
            address_=address,
            apko_=apko,
            container_=container.from_(address),
            sbom_=sbom,
        )

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
    def address(self) -> str:
        """Returns the image address"""
        return self.address_

    @function
    def container(self) -> dagger.Container:
        """Returns the image container"""
        return self.container_

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.sbom_

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the image tarball"""
        return self.container().as_tarball()

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves image platforms"""
        platforms: list[dagger.Platform] = []
        crane = self.crane()
        manifest = json.loads(await crane.manifest(image=self.address_))
        for entry in manifest.get("manifests", []):
            platform = entry["platform"]
            architecture = platform["architecture"]
            os = platform["os"]
            platforms.append(dagger.Platform(f"{os}/{architecture}"))
        return platforms

    @function
    def platform_container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the image container for the specified platform (current platform if not specified)"""
        return dag.container(platform=platform).from_(address=self.address_)

    @function
    def platform_tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container tarball for the specified platform"""
        container: dagger.Container = self.platform_container(platform=platform)
        return container.as_tarball()

    @function
    async def platform_variants(self) -> list[dagger.Container]:
        """Returns the image platform variants"""
        platform_variants: list[dagger.Container] = []
        for platform in await self.platforms():
            if platform != await self.container().platform():
                platform_variants.append(self.platform_container(platform=platform))
        return platform_variants

    @function
    def platform_sbom(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Return the SBOM for the specified platform (index if not specified)"""
        if platform is not None:
            if platform == dagger.Platform("linux/amd64"):
                return self.sbom.file("sbom-x86_64.spdx.json")
            return self.sbom.file("sbom-aarch64.spdx.json")
        return self.sbom.file("sbom-index.spdx.json")

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
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
    async def ref(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the fully qualified image ref"""
        ref = await self.crane().digest(
            image=self.address_, platform=platform, full_ref=True
        )
        return ref.strip()

    @function
    async def digest(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the image digest"""
        digest = await self.crane().digest(image=self.address_, platform=platform)
        return digest.strip()

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        result = await self.crane().tag(image=self.address_, tag=tag)
        return result

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
        return self

    @function
    async def copy(self, target: Annotated[str, Doc("Target")]) -> str:
        """Copy image to another registry"""
        result = await self.cosign().copy(
            source=self.address_, destination=target, force=True
        )
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
                str | None,
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan image using Grype"""
        grype = self.grype()
        return grype.scan_image(
            source=self.address_,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )

    @function
    async def with_scan(
        self,
        severity_cutoff: (
            Annotated[
                str | None,
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan image using Grype (for chaining)"""
        report: dagger.File = self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        await report.contents()
        return self

    @function
    async def sign(
        self,
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")] = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] = None,
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
