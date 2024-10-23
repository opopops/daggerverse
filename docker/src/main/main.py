import asyncio
from typing import Annotated

import dagger
from dagger import Doc, Name, dag, field, function, object_type

from .build import Build


@object_type
class Docker:
    """Docker CLI"""

    registry: Annotated[str, Doc("Registry host")] | None = field(
        default="index.docker.io"
    )
    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )

    def container(self, platform: dagger.Platform | None = None) -> dagger.Container:
        """Returns authentcated Docker container"""
        container: dagger.Container = dag.container(platform=platform)
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        return container

    @function
    async def build(
        self,
        context: Annotated[dagger.Directory, Doc("Dockerfile context")],
        platforms: Annotated[
            list[dagger.Platform],
            Doc("Set target platform for build"),
            Name("platform"),
        ],
        dockerfile: Annotated[str, Doc("Name of the Dockerfile"), Name("file")]
        | None = "Dockerfile",
        target: Annotated[str, Doc("Set the target build stage to build")] | None = "",
        secrets: Annotated[
            list[dagger.Secret], Doc("Secrets to pass to the build"), Name("secret")
        ]
        | None = None,
    ) -> Build:
        """Build multi-arch Docker image"""

        platform_variants: list[dagger.Container] = []

        async def build_(
            container: dagger.Container,
            context: dagger.Directory,
            dockerfile: str,
            target: str,
            secrets: list[dagger.Secret],
        ):
            container = await container.build(
                context=context, dockerfile=dockerfile, target=target, secrets=secrets
            )
            platform_variants.append(container)

        if platforms is not None:
            async with asyncio.TaskGroup() as tg:
                for platform in platforms:
                    tg.create_task(
                        build_(
                            container=self.container(platform=platform),
                            context=context,
                            dockerfile=dockerfile,
                            target=target,
                            secrets=secrets,
                        )
                    )
        else:
            platform_variants.append(
                self.container().build(
                    context=context,
                    dockerfile=dockerfile,
                    target=target,
                    secrets=secrets,
                )
            )
        return Build(
            platform_variants=platform_variants,
            registry=self.registry,
            registry_username=self.username,
            registry_password=self.password,
        )
