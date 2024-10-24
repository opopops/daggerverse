from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, field, object_type

from .image import Image as Image


@object_type
class Build:
    """Apko Build module"""

    directory: Annotated[dagger.Directory, Doc("Build directory")]

    image: Annotated[str, Doc("Apko image")] = field(
        default="cgr.dev/chainguard/bash:latest"
    )
    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container: Annotated[dagger.Container, Doc("Build container")] | None = field(
        default=None
    )

    def container_(self) -> dagger.Container:
        """Returns configured container"""
        if self.container:
            return self.container

        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.registry,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container = (
            container.from_(address=self.image)
            .with_user(self.user)
            .with_env_variable("BUILD_DIR", "/build")
            .with_env_variable("IMAGE_TAR", "${BUILD_DIR}/image.tar", expand=True)
        )
        return self.container

    def crane(self) -> dagger.Crane:
        """Returns authenticated crane"""
        crane: dagger.Crane = dag.crane()
        if self.registry_username is not None and self.registry_password is not None:
            crane = crane.with_registry_auth(
                address=self.registry,
                username=self.registry_username,
                secret=self.registry_password,
            )
        return crane

    @function
    def sbom(self) -> dagger.Directory:
        """Return"""
        return self.directory.wihtout_file("image.tar")

    @function
    def as_oci(self) -> dagger.Directory:
        """Returns the image OCI layout directory"""
        return self.directory

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
        return await grype.scan_dir(
            source=self.directory,
            scheme="dir",
            fail_on=fail_on,
            output_format=output_format,
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
    async def publish(self, image: Annotated[list[str], Doc("Image tag")]) -> str:
        """Publish multi-arch image"""
        ref: str = await self.crane().push(path=self.directory, image=image, index=True)
        return Image(
            address=ref,
            registry_username=self.registry_username,
            registry_password=self.registry_password,
        )
