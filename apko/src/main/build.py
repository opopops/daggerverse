from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, field, object_type

from .image import Image


@object_type
class Build:
    """Apko Build module"""

    directory: Annotated[dagger.Directory, Doc("OCI directory")]

    image: Annotated[str, Doc("Apko image")] = field(
        default="cgr.dev/chainguard/bash:latest"
    )
    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container_: dagger.Container | None = None

    def container(self) -> dagger.Container:
        """Returns the build container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        self.container_ = (
            container.from_(address=self.image)
            .with_user(self.user)
            .with_env_variable("BUILD_DIR", "/build")
            .with_env_variable("IMAGE_TAR", "${BUILD_DIR}/image.tar", expand=True)
        )
        return self.container_

    def crane(self) -> dagger.Crane:
        """Returns configured Crane"""
        crane: dagger.Crane = dag.crane()
        if self.username is not None and self.password is not None:
            crane = crane.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        return crane

    @function
    def sbom(self) -> dagger.Directory:
        """Returns SBOM"""
        return self.directory.wihtout_file("image.tar")

    @function
    def as_directory(self) -> dagger.Directory:
        """Returns the image OCI layout directory"""
        return self.directory

    @function
    def scan(
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
        return grype.scan_directory(
            source=self.directory,
            scheme="oci-dir",
            fail_on=fail_on,
            output_format=output_format,
        )

    @function
    def with_scan(
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
        self.scan(fail_on=fail_on, output_format=output_format)
        return self

    @function
    async def publish(self, image: Annotated[list[str], Doc("Image tag")]) -> Image:
        """Publish multi-arch image"""
        ref: str = await self.crane().push(path=self.directory, image=image, index=True)
        return Image(address=ref, username=self.username, password=self.password)
