"""
This type stub file was generated by pyright.
"""

import argparse
from __future__ import print_function
from typing import (
    Any,
    Dict,
    Generator,
    List,
    Literal,
    Optional,
    OrderedDict,
    Tuple,
    Union,
)

"""Python helper for Semantic Versioning (http://semver.org/)"""
PY2 = ...
PY3 = ...
__version__ = ...
__author__ = ...
__author_email__ = ...
__maintainer__ = ...
__maintainer_email__ = ...
SEMVER_SPEC_VERSION = ...

def comparator(operator: Any) -> Any:  # -> (self: Unknown, other: Unknown) -> Unknown:
    """Wrap a VersionInfo binary op method in a type-check."""
    ...

class VersionInfo:
    """
    A semver compatible version class.
    :param int major: version when you make incompatible API changes.
    :param int minor: version when you add functionality in
                      a backwards-compatible manner.
    :param int patch: version when you make backwards-compatible bug fixes.
    :param str prerelease: an optional prerelease string
    :param str build: an optional build string
    """

    def __init__(
        self,
        major: int,
        minor: int = ...,
        patch: int = ...,
        prerelease: Optional[str] = ...,
        build: Optional[str] = ...,
    ) -> None: ...
    @property
    def major(self) -> Any:  # -> Unknown:
        """The major part of a version (read-only)."""
        ...
    @major.setter
    def major(self, value: int) -> Any: ...
    @property
    def minor(self) -> Any:  # -> Unknown:
        """The minor part of a version (read-only)."""
        ...
    @minor.setter
    def minor(self, value: int) -> Any: ...
    @property
    def patch(self) -> Any:  # -> Unknown:
        """The patch part of a version (read-only)."""
        ...
    @patch.setter
    def patch(self, value: int) -> Any: ...
    @property
    def prerelease(self) -> Union[str, None]:  # -> str | None:
        """The prerelease part of a version (read-only)."""
        ...
    @prerelease.setter
    def prerelease(self, value: str) -> Union[str, None]: ...
    @property
    def build(self) -> Union[str, None]:  # -> str | None:
        """The build part of a version (read-only)."""
        ...
    @build.setter
    def build(self, value: str) -> Union[str, None]: ...
    def to_tuple(
        self,
    ) -> Tuple[
        Any, Any, Any, str | None, str | None
    ]:  # -> tuple[Unknown, Unknown, Unknown, str | None, str | None]:
        """
        Convert the VersionInfo object to a tuple.
        .. versionadded:: 2.10.0
           Renamed ``VersionInfo._astuple`` to ``VersionInfo.to_tuple`` to
           make this function available in the public API.
        :return: a tuple with all the parts
        :rtype: tuple
        >>> semver.VersionInfo(5, 3, 1).to_tuple()
        (5, 3, 1, None, None)
        """
        ...
    def to_dict(
        self,
    ) -> OrderedDict[
        Literal["major", "minor", "patch", "prerelease", "build"], Any
    ]:  # -> OrderedDict[Literal['major', 'minor', 'patch', 'prerelease', 'build'], Unknown]:
        """
        Convert the VersionInfo object to an OrderedDict.
        .. versionadded:: 2.10.0
           Renamed ``VersionInfo._asdict`` to ``VersionInfo.to_dict`` to
           make this function available in the public API.
        :return: an OrderedDict with the keys in the order ``major``, ``minor``,
          ``patch``, ``prerelease``, and ``build``.
        :rtype: :class:`collections.OrderedDict`
        >>> semver.VersionInfo(3, 2, 1).to_dict()
        OrderedDict([('major', 3), ('minor', 2), ('patch', 1), \
('prerelease', None), ('build', None)])
        """
        ...
    def __iter__(
        self,
    ) -> Generator[
        Any | str | None, None, None
    ]:  # -> Generator[Unknown | str | None, None, None]:
        """Implement iter(self)."""
        ...
    def bump_major(self) -> VersionInfo:  # -> VersionInfo:
        """
        Raise the major part of the version, return a new object but leave self
        untouched.
        :return: new object with the raised major part
        :rtype: :class:`VersionInfo`
        >>> ver = semver.VersionInfo.parse("3.4.5")
        >>> ver.bump_major()
        VersionInfo(major=4, minor=0, patch=0, prerelease=None, build=None)
        """
        ...
    def bump_minor(self) -> VersionInfo:  # -> VersionInfo:
        """
        Raise the minor part of the version, return a new object but leave self
        untouched.
        :return: new object with the raised minor part
        :rtype: :class:`VersionInfo`
        >>> ver = semver.VersionInfo.parse("3.4.5")
        >>> ver.bump_minor()
        VersionInfo(major=3, minor=5, patch=0, prerelease=None, build=None)
        """
        ...
    def bump_patch(self) -> VersionInfo:  # -> VersionInfo:
        """
        Raise the patch part of the version, return a new object but leave self
        untouched.
        :return: new object with the raised patch part
        :rtype: :class:`VersionInfo`
        >>> ver = semver.VersionInfo.parse("3.4.5")
        >>> ver.bump_patch()
        VersionInfo(major=3, minor=4, patch=6, prerelease=None, build=None)
        """
        ...
    def bump_prerelease(self, token: str = ...) -> VersionInfo:  # -> VersionInfo:
        """
        Raise the prerelease part of the version, return a new object but leave
        self untouched.
        :param token: defaults to 'rc'
        :return: new object with the raised prerelease part
        :rtype: :class:`VersionInfo`
        >>> ver = semver.VersionInfo.parse("3.4.5-rc.1")
        >>> ver.bump_prerelease()
        VersionInfo(major=3, minor=4, patch=5, prerelease='rc.2', \
build=None)
        """
        ...
    def bump_build(self, token: str = ...) -> VersionInfo:  # -> VersionInfo:
        """
        Raise the build part of the version, return a new object but leave self
        untouched.
        :param token: defaults to 'build'
        :return: new object with the raised build part
        :rtype: :class:`VersionInfo`
        >>> ver = semver.VersionInfo.parse("3.4.5-rc.1+build.9")
        >>> ver.bump_build()
        VersionInfo(major=3, minor=4, patch=5, prerelease='rc.1', \
build='build.10')
        """
        ...
    def compare(
        self,
        other: Union[
            str,
            Dict[str, Union[int, str]],
            Tuple[str, Union[int, str]],
            List[str],
            VersionInfo,
        ],
    ) -> int:  # -> int:
        """
        Compare self with other.
        :param other: the second version (can be string, a dict, tuple/list, or
             a VersionInfo instance)
        :return: The return value is negative if ver1 < ver2,
             zero if ver1 == ver2 and strictly positive if ver1 > ver2
        :rtype: int
        >>> semver.VersionInfo.parse("1.0.0").compare("2.0.0")
        -1
        >>> semver.VersionInfo.parse("2.0.0").compare("1.0.0")
        1
        >>> semver.VersionInfo.parse("2.0.0").compare("2.0.0")
        0
        >>> semver.VersionInfo.parse("2.0.0").compare(dict(major=2, minor=0, patch=0))
        0
        """
        ...
    def next_version(
        self,
        part: Literal["major", "minor", "patch", "prerelease", "build"],
        prerelease_token: str = ...,
    ) -> Union[Any, VersionInfo]:  # -> VersionInfo | Any:
        """
        Determines next version, preserving natural order.
        .. versionadded:: 2.10.0
        This function is taking prereleases into account.
        The "major", "minor", and "patch" raises the respective parts like
        the ``bump_*`` functions. The real difference is using the
        "preprelease" part. It gives you the next patch version of the prerelease,
        for example:
        >>> str(semver.VersionInfo.parse("0.1.4").next_version("prerelease"))
        '0.1.5-rc.1'
        :param part: One of "major", "minor", "patch", or "prerelease"
        :param prerelease_token: prefix string of prerelease, defaults to 'rc'
        :return: new object with the appropriate part raised
        :rtype: :class:`VersionInfo`
        """
        ...
    @comparator
    def __eq__(self, other: Any) -> bool: ...
    @comparator
    def __ne__(self, other: Any) -> bool: ...
    @comparator
    def __lt__(self, other: Any) -> bool: ...
    @comparator
    def __le__(self, other: Any) -> bool: ...
    @comparator
    def __gt__(self, other: Any) -> bool: ...
    @comparator
    def __ge__(self, other: Any) -> bool: ...
    def __getitem__(
        self, index: Union[int, slice]
    ) -> Union[
        Any, str, tuple[Any, str, None]
    ]:  # -> Unknown | str | tuple[Unknown | str | None, ...] | None:
        """
        self.__getitem__(index) <==> self[index]
        Implement getitem. If the part requested is undefined, or a part of the
        range requested is undefined, it will throw an index error.
        Negative indices are not supported
        :param Union[int, slice] index: a positive integer indicating the
               offset or a :func:`slice` object
        :raises: IndexError, if index is beyond the range or a part is None
        :return: the requested part of the version at position index
        >>> ver = semver.VersionInfo.parse("3.4.5")
        >>> ver[0], ver[1], ver[2]
        (3, 4, 5)
        """
        ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str:
        """str(self)"""
        ...
    def __hash__(self) -> int: ...
    def finalize_version(self) -> VersionInfo:  # -> VersionInfo:
        """
        Remove any prerelease and build metadata from the version.
        :return: a new instance with the finalized version string
        :rtype: :class:`VersionInfo`
        >>> str(semver.VersionInfo.parse('1.2.3-rc.5').finalize_version())
        '1.2.3'
        """
        ...
    def match(self, match_expr: str) -> bool:  # -> bool:
        """
        Compare self to match a match expression.
        :param str match_expr: operator and version; valid operators are
              <   smaller than
              >   greater than
              >=  greator or equal than
              <=  smaller or equal than
              ==  equal
              !=  not equal
        :return: True if the expression matches the version, otherwise False
        :rtype: bool
        >>> semver.VersionInfo.parse("2.0.0").match(">=1.0.0")
        True
        >>> semver.VersionInfo.parse("1.0.0").match(">1.0.0")
        False
        """
        ...
    @classmethod
    def parse(cls, version: str) -> VersionInfo:  # -> VersionInfo:
        """
        Parse version string to a VersionInfo instance.
        :param version: version string
        :return: a :class:`VersionInfo` instance
        :raises: :class:`ValueError`
        :rtype: :class:`VersionInfo`
        .. versionchanged:: 2.11.0
           Changed method from static to classmethod to
           allow subclasses.
        >>> semver.VersionInfo.parse('3.4.5-pre.2+build.4')
        VersionInfo(major=3, minor=4, patch=5, \
prerelease='pre.2', build='build.4')
        """
        ...
    def replace(self, **parts: Union[int, str, None]) -> VersionInfo:  # -> VersionInfo:
        """
        Replace one or more parts of a version and return a new
        :class:`VersionInfo` object, but leave self untouched
        .. versionadded:: 2.9.0
           Added :func:`VersionInfo.replace`
        :param dict parts: the parts to be updated. Valid keys are:
          ``major``, ``minor``, ``patch``, ``prerelease``, or ``build``
        :return: the new :class:`VersionInfo` object with the changed
          parts
        :raises: :class:`TypeError`, if ``parts`` contains invalid keys
        """
        ...
    @classmethod
    def isvalid(cls, version: str) -> bool:  # -> bool:
        """
        Check if the string is a valid semver version.
        .. versionadded:: 2.9.1
        :param str version: the version string to check
        :return: True if the version string is a valid semver version, False
                 otherwise.
        :rtype: bool
        """
        ...

def cmd_bump(args: argparse.Namespace) -> str:  # -> str:
    """
    Subcommand: Bumps a version.
    Synopsis: bump <PART> <VERSION>
    <PART> can be major, minor, patch, prerelease, or build
    :param args: The parsed arguments
    :type args: :class:`argparse.Namespace`
    :return: the new, bumped version
    """
    ...

def cmd_check(args: argparse.Namespace) -> None:  # -> None:
    """
    Subcommand: Checks if a string is a valid semver version.
    Synopsis: check <VERSION>
    :param args: The parsed arguments
    :type args: :class:`argparse.Namespace`
    """
    ...

def cmd_compare(args: argparse.Namespace) -> str:  # -> str:
    """
    Subcommand: Compare two versions
    Synopsis: compare <VERSION1> <VERSION2>
    :param args: The parsed arguments
    :type args: :class:`argparse.Namespace`
    """
    ...

def cmd_nextver(args: argparse.Namespace) -> str:  # -> str:
    """
    Subcommand: Determines the next version, taking prereleases into account.
    Synopsis: nextver <VERSION> <PART>
    :param args: The parsed arguments
    :type args: :class:`argparse.Namespace`
    """
    ...

def createparser() -> argparse.ArgumentParser:  # -> ArgumentParser:
    """
    Create an :class:`argparse.ArgumentParser` instance.
    :return: parser instance
    :rtype: :class:`argparse.ArgumentParser`
    """
    ...

def process(args: argparse.Namespace) -> str:
    """
    Process the input from the CLI.
    :param args: The parsed arguments
    :type args: :class:`argparse.Namespace`
    :param parser: the parser instance
    :type parser: :class:`argparse.ArgumentParser`
    :return: result of the selected action
    :rtype: str
    """
    ...

def main(cliargs: Any = ...) -> Literal[0, 2]:  # -> Literal[0, 2]:
    """
    Entry point for the application script.
    :param list cliargs: Arguments to parse or None (=use :class:`sys.argv`)
    :return: error code
    :rtype: int
    """
    ...

if __name__ == "__main__": ...
