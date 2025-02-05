import json
from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, dag, field, function, object_type


@object_type
class Image:
    """Docker Image"""

    address: Annotated[str, Doc("Image address")]

    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns authenticated container"""
        if self.container_:
            return self.container_
        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.address,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container_ = container.from_(self.address)
        return self.container_

    async def crane(self) -> dagger.Crane:
        """Returns authenticated crane"""
        crane: dagger.Crane = dag.crane()
        if self.registry_username is not None and self.registry_password is not None:
            crane = crane.with_registry_auth(
                address=await self.registry(),
                username=self.registry_username,
                secret=self.registry_password,
            )
        return crane

    async def cosign(self) -> dagger.Cosign:
        """Returns authenticated cosign"""
        cosign: dagger.Cosign = dag.cosign()
        if self.registry_username is not None and self.registry_password is not None:
            cosign = cosign.with_registry_auth(
                address=await self.registry(),
                username=self.registry_username,
                secret=self.registry_password,
            )
        return cosign

    async def grype(self) -> dagger.Grype:
        """Returns authenticated grype"""
        grype: dagger.Grype = dag.grype()
        if self.registry_username is not None and self.registry_password is not None:
            grype = grype.with_registry_auth(
                address=await self.registry(),
                username=self.registry_username,
                secret=self.registry_password,
            )
        return grype

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves image platforms"""
        platforms: list[dagger.Platform] = []
        crane = await self.crane()

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
        return await self.container().image_ref()

    @function
    async def digest(self) -> str:
        """Retrieves the image digest"""
        crane = await self.crane()
        return await crane.digest(image=self.address)

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        crane = await self.crane()
        return await crane.tag(image=self.address, tag=tag)

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
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan image using Grype"""
        grype = await self.grype()
        return grype.scan_image(
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
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan image using Grype (for chaining)"""
        await self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        return self

    @function
    async def sign(
        self,
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")],
        password: Annotated[dagger.Secret, Doc("Cosign password")],
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = True,
    ) -> str:
        """Sign image with Cosign"""
        cosign = await self.cosign()
        return await cosign.sign(
            image=await self.ref(),
            private_key=private_key,
            password=password,
            recursive=recursive,
        )

    @function
    async def with_sign(
        self,
        private_key: Annotated[dagger.Secret, Doc("Cosign private key")],
        password: Annotated[dagger.Secret, Doc("Cosign password")],
        recursive: Annotated[
            bool,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ] = False,
    ) -> Self:
        """Sign image with Cosign (for chaining)"""
        await self.sign(private_key=private_key, password=password, recursive=recursive)
        return self
