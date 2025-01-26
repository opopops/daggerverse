import json
from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Image:
    """Apko Image module"""

    address: Annotated[str, Doc("Image address")]

    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )

    container_: dagger.Container | None = None

    @function
    def container(self, platform: dagger.Platform | None = None) -> dagger.Container:
        """Returns authenticated container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container(platform=platform)
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.address, username=self.username, secret=self.password
            )
        self.container_ = container.from_(self.address)
        return self.container_

    async def crane(self) -> dagger.Crane:
        """Returns authenticated crane"""
        crane: dagger.Crane = dag.crane()
        if self.username is not None and self.password is not None:
            crane = crane.with_registry_auth(
                address=await self.registry(),
                username=self.username,
                secret=self.password,
            )
        return crane

    async def cosign(self) -> dagger.Cosign:
        """Returns authenticated cosign"""
        cosign: dagger.Cosign = dag.cosign()
        if self.username is not None and self.password is not None:
            cosign = cosign.with_registry_auth(
                address=await self.registry(),
                username=self.username,
                secret=self.password,
            )
        return cosign

    async def grype(self) -> dagger.Grype:
        """Returns authenticated grype"""
        grype: dagger.Grype = dag.grype()
        if self.username is not None and self.password is not None:
            grype = grype.with_registry_auth(
                address=await self.registry(),
                username=self.username,
                secret=self.password,
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
        return await self.container().image_ref().strip()

    @function
    async def digest(self) -> str:
        """Retrieves the image digest"""
        crane = await self.crane()
        return await crane.digest(image=self.address).strip()

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        crane = await self.crane()
        result = await crane.tag(image=self.address, tag=tag)
        self.address = tag
        self.container_ = None
        return result

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
        return self

    @function
    async def copy(self, target: Annotated[str, Doc("Target")]) -> str:
        """Copy image to another registry"""
        crane = await self.crane()
        result = await crane.copy(source=self.address, target=target)
        self.address = target
        self.container_ = None
        return result

    @function
    async def with_copy(self, target: Annotated[str, Doc("Target")]) -> Self:
        """Copy image to another registry (for chaining)"""
        await self.copy(target=target)
        return self

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
        """Scan image using Grype"""
        grype = await self.grype()
        return grype.scan_image(
            source=self.address, fail_on=fail_on, output_format=output_format
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
        """Scan image using Grype (for chaining)"""
        await self.scan(fail_on=fail_on, output_format=output_format)
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
