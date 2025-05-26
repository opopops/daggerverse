import json
from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, dag, field, function, object_type

from .cli import Cli
from .sbom import Sbom


@object_type
class Image:
    """Image"""

    address: str = field()
    container_: dagger.Container
    sbom_: Sbom

    apko: Cli

    def docker_config(self) -> dagger.File:
        """Returns the docker config file"""
        return self.apko.container().file("${DOCKER_CONFIG}/config.json", expand=True)

    def crane(self) -> dagger.Crane:
        """Returns crane"""
        return dag.crane(docker_config=self.docker_config())

    def cosign(self) -> dagger.Cosign:
        """Returns cosign"""
        return dag.cosign(docker_config=self.docker_config())

    def grype(self) -> dagger.Grype:
        """Returns grype"""
        return dag.grype(docker_config=self.docker_config())

    async def platform_variants(self) -> list[dagger.Container]:
        """Returns the image platform variants"""
        platform_variants: list[dagger.Container] = []
        for platform in await self.platforms():
            if platform != await self.container().platform():
                platform_variants.append(self.container(platform=platform))
        return platform_variants

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.sbom_.directory()

    @function
    def sbom_file(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Return the SBOM for the specified platform (index if not specified)"""
        return self.sbom_.file(platform=platform)

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
    async def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container for the specified platform (current platform if not specified)"""
        if platform:
            if platform == await self.container_.platform():
                return self.container_
            return dag.container(platform=platform).from_(address=self.address)
        return self.container_

    @function
    def tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container tarball for the specified platform"""
        container: dagger.Container = self.container(platform=platform)
        return container.as_tarball()

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
        self.apko = self.apko.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def ref(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the fully qualified image ref"""
        ref = await self.crane().digest(
            image=self.address, platform=platform, full_ref=True
        )
        return ref.strip()

    @function
    async def digest(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the image digest"""
        digest = await self.crane().digest(image=self.address, platform=platform)
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
        result = await self.cosign().copy(
            source=self.address, destination=target, force=True
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
        severity: (
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
            source=self.address,
            severity_cutoff=severity,
            fail=fail,
            output_format=output_format,
        )

    @function
    async def with_scan(
        self,
        severity: (
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
            severity=severity, fail=fail, output_format=output_format
        )
        await report.contents()
        return self

    @function
    async def sign(
        self,
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
    ) -> str:
        """Sign image with Cosign"""
        return await self.cosign().sign(
            image=await self.ref(),
            private_key=private_key,
            password=password,
            identity_token=identity_token,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=True,
        )

    @function
    async def with_sign(
        self,
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
    ) -> Self:
        """Sign image with Cosign (for chaining)"""
        await self.sign(
            private_key=private_key,
            password=password,
            identity_token=identity_token,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
        )
        return self

    @function
    async def attest(
        self,
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
    ) -> str:
        """Attest image SBOMs with Cosign"""
        for platform in await self.platforms():
            await self.cosign().attest(
                image=await self.ref(),
                predicate=self.sbom_file(platform=platform),
                type_="spdxjson",
                private_key=private_key,
                password=password,
                identity_token=identity_token,
                oidc_provider=oidc_provider,
                oidc_issuer=oidc_issuer,
            )
        # Attest index SBOM
        return await self.cosign().attest(
            image=await self.ref(),
            predicate=self.sbom_file(),
            type_="spdxjson",
            private_key=private_key,
            password=password,
            identity_token=identity_token,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
        )

    @function
    async def with_attest(
        self,
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
    ) -> Self:
        """Attest image SBOMs with Cosign (for chaining)"""
        await self.attest(
            private_key=private_key,
            password=password,
            identity_token=identity_token,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
        )
        return self
