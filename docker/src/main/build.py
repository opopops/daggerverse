from typing import Annotated, Self

import dagger
from dagger import Doc, dag, field, function, object_type

from .image import Image


@object_type
class Build:
    """Docker Build"""

    platform_variants: Annotated[list[dagger.Container], Doc("Platform variants build")]

    registry: Annotated[str, Doc("Registry host")] | None = field(default="docker.io")
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )

    build_container_: dagger.Container | None = None
    platform_container_: dagger.Container | None = None

    def build_container(self) -> dagger.Container:
        """Returns the build container"""
        if self.build_container_:
            return self.build_container_
        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.registry,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.build_container_ = container
        return self.build_container_

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = []
        for platform_variant in self.platform_variants:
            platforms.append(await platform_variant.platform())
        return platforms

    @function(name="container")
    async def platform_container(self) -> dagger.Container:
        """Returns the current host platform variant container"""
        if self.platform_container_:
            return self.platform_container_
        container: dagger.Container = dag.container()
        for platform_variant in self.platform_variants:
            if await platform_variant.platform() == await container.platform():
                self.platform_container_ = platform_variant
                return self.platform_container_

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.build_container()
        self.build_container_ = container.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def as_tarball(
        self, compress: Annotated[bool, Doc("Enable compression")] = False
    ) -> dagger.File:
        """Export container as tarball"""
        forced_compression = dagger.ImageLayerCompression("Uncompressed")
        if compress:
            forced_compression = dagger.ImageLayerCompression("Gzip")
        container: dagger.Container = await self.platform_container()
        return container.as_tarball(forced_compression=forced_compression)

    @function
    async def scan(
        self,
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan build result using Grype"""
        grype = dag.grype()
        return grype.scan_file(
            source=await self.as_tarball(),
            source_type="oci-archive",
            fail_on=fail_on,
            output_format=output_format,
        )

    @function
    async def with_scan(
        self,
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan build result using Grype (for chaining)"""
        await self.scan(fail_on=fail_on, output_format=output_format)
        return self

    @function
    async def publish(self, image: Annotated[str, Doc("Image tags")]) -> Image:
        """Publish multi-arch image"""
        ref: str = None
        container: dagger.Container = self.build_container()
        ref = await container.publish(
            address=image, platform_variants=self.platform_variants
        )
        return Image(
            address=ref,
            username=self.registry_username,
            password=self.registry_password,
        )
