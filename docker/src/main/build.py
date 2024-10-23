from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, field, function, object_type

from .image import Image as Image


@object_type
class Build:
    """Docker Build"""

    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )

    platform_variants: Annotated[
        list[dagger.Container], Doc("Platform variants"), Name("container")
    ]

    @function
    async def container(self) -> dagger.Container:
        container: dagger.Container = dag.container()
        for platform_variant in self.platform_variants:
            if await platform_variant.platform() == await container.platform():
                return platform_variant

    @function
    async def export(
        self, compress: Annotated[bool, Doc("Enable compression")] | None = False
    ) -> dagger.File:
        """Export build as tarball"""
        forced_compression = dagger.ImageLayerCompression("Uncompressed")
        if compress:
            forced_compression = dagger.ImageLayerCompression("Gzip")
        return dag.container().as_tarball(
            forced_compression=forced_compression,
            platform_variants=self.platform_variants,
        )

    @function
    async def grype(
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
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> str:
        """Scan build result using Grype"""
        grype = dag.grype()
        tarball = await self.export()
        return await grype.scan_tarball(
            tarball=tarball, fail_on=fail_on, output_format=output_format
        )

    @function
    async def with_grype(
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
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan build result using Grype (for chaining)"""
        await self.grype(fail_on=fail_on, output_format=output_format)
        return self

    @function
    async def publish(
        self, images: Annotated[list[str], Doc("Image tags"), Name("image")]
    ) -> Image:
        """Publish multi-arch image"""
        ref: str = None
        for image in images:
            ref = await dag.container().publish(
                address=image, platform_variants=self.platform_variants
            )
        return Image(
            address=ref,
            registry_username=self.registry_username,
            registry_password=self.registry_password,
        )
