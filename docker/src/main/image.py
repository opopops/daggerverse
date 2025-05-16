import json
from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, dag, field, function, object_type


@object_type
class Image:
    """Docker Image"""

    address: str = field()
    container_: dagger.Container | None = None

    crane: dagger.Crane | None = None
    cosign: dagger.Cosign | None = None
    grype: dagger.Grype | None = None

    @classmethod
    async def create(
        cls,
        address: Annotated[str, Doc("Image address")],
        container: Annotated[dagger.Container | None, Doc("Image container")] = None,
    ):
        """Constructor"""
        if container is None:
            container = dag.container().from_(address)
        return cls(
            address=address,
            container_=container,
            crane=dag.crane(),
            cosign=dag.cosign(),
            grype=dag.grype(),
        )

    @function
    def container(self) -> dagger.Container:
        """Returns image container"""
        self.container_ = self.container_.from_(self.address)
        return self.container_

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.crane = self.crane.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.cosign = self.cosign.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.grype = self.grype.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves image platforms"""
        platforms: list[dagger.Platform] = []
        manifest = json.loads(await self.crane.manifest(image=self.address))

        for entry in manifest.get("manifests", []):
            platform = entry["platform"]
            architecture = platform["architecture"]
            os = platform["os"]
            platforms.append(dagger.Platform(f"{os}/{architecture}"))
        return platforms

    @function
    async def ref(self) -> str:
        """Retrieves the fully qualified image ref"""
        return await self.container().image_ref()

    @function
    async def digest(self) -> str:
        """Retrieves the image digest"""
        return await self.crane.digest(image=self.address)

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        return await self.crane.tag(image=self.address, tag=tag)

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
        return self

    @function
    async def scan(
        self,
        severity_cutoff: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan image using Grype"""
        return self.grype.scan_image(
            source=self.address,
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
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan image using Grype (for chaining)"""
        await self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        return self

    @function
    async def sign(
        self,
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")]
        | None = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ]
        | None = None,
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = True,
    ) -> str:
        """Sign image with Cosign"""
        return await self.cosign.sign(
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
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")]
        | None = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ]
        | None = None,
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = True,
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
