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

    container: Annotated[dagger.Container, Doc("Container")] | None = field(
        default=None
    )

    def container_(self, platform: dagger.Platform | None = None) -> dagger.Container:
        """Returns authenticated container"""
        if self.container:
            return self.container

        container: dagger.Container = dag.container(platform=platform)
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.address,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container = container.from_(self.address)
        return self.container

    def crane(self) -> dagger.Crane:
        """Returns authenticated crane"""
        crane: dagger.Crane = dag.crane()
        if self.registry_username is not None and self.registry_password is not None:
            crane = crane.with_registry_auth(
                address=self.registry(),
                username=self.registry_username,
                secret=self.registry_password,
            )
        return crane

    def cosign(self) -> dagger.Cosign:
        """Returns authenticated cosign"""
        cosign: dagger.Cosign = dag.cosign()
        if self.registry_username is not None and self.registry_password is not None:
            cosign = cosign.with_registry_auth(
                address=self.registry(),
                username=self.registry_username,
                secret=self.registry_password,
            )
        return cosign

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

    async def platform_variants(self) -> list[dagger.Container]:
        """Retireves multi-arch image platform variants"""
        platform_variants: list[dagger.Container] = []
        platforms = await self.platforms()
        if platforms:
            for platform in platforms:
                platform_variants.append(self.container(platform=platform))
        else:
            platform_variants.append(self.container_())
        return platform_variants

    @function
    async def ref(self) -> str:
        """Retrieves the fully qualified image ref"""
        return await self.container_().image_ref()

    @function
    async def digest(self) -> str:
        """Retrieves the image digest"""
        crane = self.crane()
        return await crane.digest(image=self.address)

    @function
    def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{self.address}")
        return url.netloc

    @function
    async def publish(self, image: Annotated[str, Doc("Image tag")]) -> str:
        """Tag image"""
        return await self.container_().publish(
            address=image, platform_variants=await self.platform_variants()
        )

    @function
    async def with_publish(self, image: Annotated[str, Doc("Image tag")]) -> Self:
        """Tag image and return Image (for chaining)"""
        await self.publish(image=image)
        return Self

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        crane = self.crane()
        return await crane.tag(image=self.address, tag=tag)

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
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
        ]
        | None = True,
    ) -> str:
        """Sign image with Cosign"""
        cosign = self.cosign()
        return await cosign.sign(
            digest=await self.ref(),
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
        ]
        | None = True,
    ) -> str:
        """Sign image with Cosign (for chaining)"""
        await self.cosign(
            private_key=private_key, password=password, recursive=recursive
        )
        return self
