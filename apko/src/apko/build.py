from typing import Annotated, Self
from datetime import datetime

import dagger
from dagger import Doc, Name, dag, function, object_type

from .cli import Cli
from .image import Image
from .sbom import Sbom


@object_type
class Build:
    """Apko Build"""

    tarball_: dagger.File
    container_: dagger.Container
    platform_variants: list[dagger.Container]
    sbom_: Sbom

    apko: Cli

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the build as tarball"""
        return self.tarball_

    @function
    def as_directory(self) -> dagger.Directory:
        """Returns the build as directory including tarball and sbom dir"""
        return self.sbom_.directory().with_file("image.tar", self.as_tarball())

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.sbom_.directory()

    @function
    def sbom_file(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the SBOM for the specified platform (index if not specified)"""
        return self.sbom_.file(platform=platform)

    @function
    async def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container for the specified platform (current platform if not specified)"""
        if platform:
            if platform == await self.container_.platform():
                return self.container_
            for platform_variant in self.platform_variants:
                if await platform_variant.platform() == platform:
                    return platform_variant
        return self.container_

    @function
    async def tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container tarball for the specified platform"""
        container: dagger.Container = await self.container(platform=platform)
        return container.as_tarball()

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = [await self.container_.platform()]
        for platform_variant in self.platform_variants:
            platforms.append(await platform_variant.platform())
        return platforms

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
        """Scan build result using Grype"""
        return dag.grype().scan_file(
            source=self.container_.as_tarball(),
            source_type="oci-archive",
            severity=severity,
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
        """Scan build result using Grype (for chaining)"""
        report: dagger.File = self.scan(
            severity=severity, fail=fail, output_format=output_format
        )
        await report.contents()
        return self

    @function
    async def publish(
        self,
        tags: Annotated[list[str], Doc("Tags"), Name("tag")],
        force: Annotated[
            bool | None, Doc("Force image publishing (invalidate cache)")
        ] = False,
    ) -> Image:
        """Publish image"""
        container: dagger.Container = self.container_
        if force:
            # Cache buster
            container = container.with_env_variable("CACHEBUSTER", str(datetime.now()))
        ref: str = ""
        for tag in tags:
            ref = await container.publish(
                address=tag, platform_variants=self.platform_variants
            )
        return Image(
            address=ref,
            container_=container,
            sbom_=self.sbom_,
            apko=self.apko,
        )
