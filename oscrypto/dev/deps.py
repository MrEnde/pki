# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import subprocess
import sys
import shutil
import re
import json
import tarfile
import zipfile

from . import package_root, build_root, other_packages
from ._pep425 import _pep425tags, _pep425_implementation

if sys.version_info < (3,):
    str_cls = unicode  # noqa
else:
    str_cls = str


def run():
    """
    Installs required development dependencies. Uses git to checkout other
    modularcrypto repos for more accurate coverage data.
    """

    deps_dir = os.path.join(build_root, 'modularcrypto-deps')
    if os.path.exists(deps_dir):
        shutil.rmtree(deps_dir, ignore_errors=True)
    os.mkdir(deps_dir)

    try:
        print("Staging ci dependencies")
        _stage_requirements(deps_dir, os.path.join(package_root, 'requires', 'ci'))

        print("Checking out modularcrypto packages for coverage")
        for other_package in other_packages:
            pkg_url = 'https://github.com/wbond/%s.git' % other_package
            pkg_dir = os.path.join(build_root, other_package)
            if os.path.exists(pkg_dir):
                print("%s is already present" % other_package)
                continue
            print("Cloning %s" % pkg_url)
            _execute(['git', 'clone', pkg_url], build_root)
        print()

    except (Exception):
        if os.path.exists(deps_dir):
            shutil.rmtree(deps_dir, ignore_errors=True)
        raise

    return True


def _download(url, dest):
    """
    Downloads a URL to a directory

    :param url:
        The URL to download

    :param dest:
        The path to the directory to save the file in

    :return:
        The filesystem path to the saved file
    """

    print('Downloading %s' % url)
    filename = os.path.basename(url)
    dest_path = os.path.join(dest, filename)

    if sys.platform == 'win32':
        powershell_exe = os.path.join('system32\\WindowsPowerShell\\v1.0\\powershell.exe')
        code = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;"
        code += "(New-Object Net.WebClient).DownloadFile('%s', '%s');" % (url, dest_path)
        _execute([powershell_exe, '-Command', code], dest, 'Unable to connect to')

    else:
        _execute(
            ['curl', '-L', '--silent', '--show-error', '-O', url],
            dest,
            'Failed to connect to'
        )

    return dest_path


def _tuple_from_ver(version_string):
    """
    :param version_string:
        A unicode dotted version string

    :return:
        A tuple of integers
    """

    match = re.search(
        r'(\d+(?:\.\d+)*)'
        r'([-._]?(?:alpha|a|beta|b|preview|pre|c|rc)\.?\d*)?'
        r'(-\d+|(?:[-._]?(?:rev|r|post)\.?\d*))?'
        r'([-._]?dev\.?\d*)?',
        version_string
    )
    if not match:
        return tuple()

    nums = tuple(map(int, match.group(1).split('.')))

    pre = match.group(2)
    if pre:
        pre = pre.replace('alpha', 'a')
        pre = pre.replace('beta', 'b')
        pre = pre.replace('preview', 'rc')
        pre = pre.replace('pre', 'rc')
        pre = re.sub(r'(?<!r)c', 'rc', pre)
        pre = pre.lstrip('._-')
        pre_dig_match = re.search(r'\d+', pre)
        if pre_dig_match:
            pre_dig = int(pre_dig_match.group(0))
        else:
            pre_dig = 0
        pre = pre.rstrip('0123456789')

        pre_num = {
            'a': -3,
            'b': -2,
            'rc': -1,
        }[pre]

        pre_tup = (pre_num, pre_dig)
    else:
        pre_tup = tuple()

    post = match.group(3)
    if post:
        post_dig_match = re.search(r'\d+', post)
        if post_dig_match:
            post_dig = int(post_dig_match.group(0))
        else:
            post_dig = 0
        post_tup = (1, post_dig)
    else:
        post_tup = tuple()

    dev = match.group(4)
    if dev:
        dev_dig_match = re.search(r'\d+', dev)
        if dev_dig_match:
            dev_dig = int(dev_dig_match.group(0))
        else:
            dev_dig = 0
        dev_tup = (-4, dev_dig)
    else:
        dev_tup = tuple()

    normalized = [nums]
    if pre_tup:
        normalized.append(pre_tup)
    if post_tup:
        normalized.append(post_tup)
    if dev_tup:
        normalized.append(dev_tup)
    # This ensures regular releases happen after dev and prerelease, but
    # before post releases
    if not pre_tup and not post_tup and not dev_tup:
        normalized.append((0, 0))

    return tuple(normalized)


def _open_archive(path):
    """
    :param path:
        A unicode string of the filesystem path to the archive

    :return:
        An archive object
    """

    if path.endswith('.zip'):
        return zipfile.ZipFile(path, 'r')
    return tarfile.open(path, 'r')


def _list_archive_members(archive):
    """
    :param archive:
        An archive from _open_archive()

    :return:
        A list of info objects to be used with _info_name() and _extract_info()
    """

    if isinstance(archive, zipfile.ZipFile):
        return archive.infolist()
    return archive.getmembers()


def _archive_single_dir(archive):
    """
    Check if all members of the archive are in a single top-level directory

    :param archive:
        An archive from _open_archive()

    :return:
        None if not a single top level directory in archive, otherwise a
        unicode string of the top level directory name
    """

    common_root = None
    for info in _list_archive_members(archive):
        fn = _info_name(info)
        if fn in set(['.', '/']):
            continue
        sep = None
        if '/' in fn:
            sep = '/'
        elif '\\' in fn:
            sep = '\\'
        if sep is None:
            root_dir = fn
        else:
            root_dir, _ = fn.split(sep, 1)
        if common_root is None:
            common_root = root_dir
        else:
            if common_root != root_dir:
                return None
    return common_root


def _info_name(info):
    """
    Returns a normalized file path for an archive info object

    :param info:
        An info object from _list_archive_members()

    :return:
        A unicode string with all directory separators normalized to "/"
    """

    if isinstance(info, zipfile.ZipInfo):
        return info.filename.replace('\\', '/')
    return info.name.replace('\\', '/')


def _extract_info(archive, info):
    """
    Extracts the contents of an archive info object

    ;param archive:
        An archive from _open_archive()

    :param info:
        An info object from _list_archive_members()

    :return:
        None, or a byte string of the file contents
    """

    if isinstance(archive, zipfile.ZipFile):
        fn = info.filename
        is_dir = fn.endswith('/') or fn.endswith('\\')
        out = archive.read(info)
        if is_dir and out == b'':
            return None
        return out

    info_file = archive.extractfile(info)
    if info_file:
        return info_file.read()
    return None


def _extract_package(deps_dir, pkg_path, pkg_dir):
    """
    Extract a .whl, .zip, .tar.gz or .tar.bz2 into a package path to
    use when running CI tasks

    :param deps_dir:
        A unicode string of the directory the package should be extracted to

    :param pkg_path:
        A unicode string of the path to the archive

    :param pkg_dir:
        If running setup.py, change to this dir first - a unicode string
    """

    if pkg_path.endswith('.exe'):
        try:
            zf = None
            zf = zipfile.ZipFile(pkg_path, 'r')
            # Exes have a PLATLIB folder containing everything we want
            for zi in zf.infolist():
                if not zi.filename.startswith('PLATLIB'):
                    continue
                data = _extract_info(zf, zi)
                if data is not None:
                    dst_path = os.path.join(deps_dir, zi.filename[8:])
                    dst_dir = os.path.dirname(dst_path)
                    if not os.path.exists(dst_dir):
                        os.makedirs(dst_dir)
                    with open(dst_path, 'wb') as f:
                        f.write(data)
        finally:
            if zf:
                zf.close()
        return

    if pkg_path.endswith('.whl'):
        try:
            zf = None
            zf = zipfile.ZipFile(pkg_path, 'r')
            # Wheels contain exactly what we need and nothing else
            zf.extractall(deps_dir)
        finally:
            if zf:
                zf.close()
        return

    # Source archives may contain a bunch of other things, including multiple
    # packages, so we must use setup.py/setuptool to install/extract it

    ar = None
    staging_dir = os.path.join(deps_dir, '_staging')
    try:
        ar = _open_archive(pkg_path)

        common_root = _archive_single_dir(ar)

        members = []
        for info in _list_archive_members(ar):
            dst_rel_path = _info_name(info)
            if common_root is not None:
                dst_rel_path = dst_rel_path[len(common_root) + 1:]
            members.append((info, dst_rel_path))

        if not os.path.exists(staging_dir):
            os.makedirs(staging_dir)

        for info, rel_path in members:
            info_data = _extract_info(ar, info)
            # Dirs won't return a file
            if info_data is not None:
                dst_path = os.path.join(staging_dir, rel_path)
                dst_dir = os.path.dirname(dst_path)
                if not os.path.exists(dst_dir):
                    os.makedirs(dst_dir)
                with open(dst_path, 'wb') as f:
                    f.write(info_data)

        setup_dir = staging_dir
        if pkg_dir:
            setup_dir = os.path.join(staging_dir, pkg_dir)

        root = os.path.abspath(os.path.join(deps_dir, '..'))
        install_lib = os.path.basename(deps_dir)

        # Ensure we pick up previously installed packages when running
        # setup.py. This is important for things like setuptools.
        env = os.environ.copy()
        if sys.version_info >= (3,):
            env['PYTHONPATH'] = deps_dir
        else:
            env[b'PYTHONPATH'] = deps_dir.encode('utf-8')

        _execute(
            [
                sys.executable,
                'setup.py',
                'install',
                '--root=%s' % root,
                '--install-lib=%s' % install_lib,
                '--no-compile'
            ],
            setup_dir,
            env=env
        )

    finally:
        if ar:
            ar.close()
        if staging_dir:
            shutil.rmtree(staging_dir)


def _sort_pep440_versions(releases, include_prerelease):
    """
    :param releases:
        A list of unicode string PEP 440 version numbers

    :param include_prerelease:
        A boolean indicating if prerelease versions should be included

    :return:
        A sorted generator of 2-element tuples:
         0: A unicode string containing a PEP 440 version number
         1: A tuple of tuples containing integers - this is the output of
            _tuple_from_ver() for the PEP 440 version number and is intended
            for comparing versions
    """

    parsed_versions = []
    for v in releases:
        t = _tuple_from_ver(v)
        if not include_prerelease and t[1][0] < 0:
            continue
        parsed_versions.append((v, t))

    return sorted(parsed_versions, key=lambda v: v[1])


def _is_valid_python_version(python_version, requires_python):
    """
    Verifies the "python_version" and "requires_python" keys from a PyPi
    download record are applicable to the current version of Python

    :param python_version:
        The "python_version" value from a PyPi download JSON structure. This
        should be one of: "py2", "py3", "py2.py3" or "source".

    :param requires_python:
        The "requires_python" value from a PyPi download JSON structure. This
        will be None, or a comma-separated list of conditions that must be
        true. Ex: ">=3.5", "!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,>=2.7"
    """

    if python_version == "py2" and sys.version_info >= (3,):
        return False
    if python_version == "py3" and sys.version_info < (3,):
        return False

    if requires_python is not None:

        def _ver_tuples(ver_str):
            ver_str = ver_str.strip()
            if ver_str.endswith('.*'):
                ver_str = ver_str[:-2]
            cond_tup = tuple(map(int, ver_str.split('.')))
            return (sys.version_info[:len(cond_tup)], cond_tup)

        for part in map(str_cls.strip, requires_python.split(',')):
            if part.startswith('!='):
                sys_tup, cond_tup = _ver_tuples(part[2:])
                if sys_tup == cond_tup:
                    return False
            elif part.startswith('>='):
                sys_tup, cond_tup = _ver_tuples(part[2:])
                if sys_tup < cond_tup:
                    return False
            elif part.startswith('>'):
                sys_tup, cond_tup = _ver_tuples(part[1:])
                if sys_tup <= cond_tup:
                    return False
            elif part.startswith('<='):
                sys_tup, cond_tup = _ver_tuples(part[2:])
                if sys_tup > cond_tup:
                    return False
            elif part.startswith('<'):
                sys_tup, cond_tup = _ver_tuples(part[1:])
                if sys_tup >= cond_tup:
                    return False
            elif part.startswith('=='):
                sys_tup, cond_tup = _ver_tuples(part[2:])
                if sys_tup != cond_tup:
                    return False

    return True


def _locate_suitable_download(downloads):
    """
    :param downloads:
        A list of dicts containing a key "url", "python_version" and
        "requires_python"

    :return:
        A unicode string URL, or None if not a valid release for the current
        version of Python
    """

    valid_tags = _pep425tags()

    exe_suffix = None
    if sys.platform == 'win32' and _pep425_implementation() == 'cp':
        win_arch = 'win32' if sys.maxsize == 2147483647 else 'win-amd64'
        version_info = sys.version_info
        exe_suffix = '.%s-py%d.%d.exe' % (win_arch, version_info[0], version_info[1])

    wheels = {}
    whl = None
    tar_bz2 = None
    tar_gz = None
    exe = None
    for download in downloads:
        if not _is_valid_python_version(download.get('python_version'), download.get('requires_python')):
            continue

        if exe_suffix and download['url'].endswith(exe_suffix):
            exe = download['url']
        if download['url'].endswith('.whl'):
            parts = os.path.basename(download['url']).split('-')
            tag_impl = parts[-3]
            tag_abi = parts[-2]
            tag_arch = parts[-1].split('.')[0]
            wheels[(tag_impl, tag_abi, tag_arch)] = download['url']
        if download['url'].endswith('.tar.bz2'):
            tar_bz2 = download['url']
        if download['url'].endswith('.tar.gz'):
            tar_gz = download['url']

    # Find the most-specific wheel possible
    for tag in valid_tags:
        if tag in wheels:
            whl = wheels[tag]
            break

    if exe_suffix and exe:
        url = exe
    elif whl:
        url = whl
    elif tar_bz2:
        url = tar_bz2
    elif tar_gz:
        url = tar_gz
    else:
        return None

    return url


def _stage_requirements(deps_dir, path):
    """
    Installs requirements without using Python to download, since
    different services are limiting to TLS 1.2, and older version of
    Python do not support that

    :param deps_dir:
        A unicode path to a temporary directory to use for downloads

    :param path:
        A unicode filesystem path to a requirements file
    """

    packages = _parse_requires(path)
    for p in packages:
        url = None
        pkg = p['pkg']
        pkg_sub_dir = None
        if p['type'] == 'url':
            anchor = None
            if '#' in pkg:
                pkg, anchor = pkg.split('#', 1)
                if '&' in anchor:
                    parts = anchor.split('&')
                else:
                    parts = [anchor]
                for part in parts:
                    param, value = part.split('=')
                    if param == 'subdirectory':
                        pkg_sub_dir = value

            if pkg.endswith('.zip') or pkg.endswith('.tar.gz') or pkg.endswith('.tar.bz2') or pkg.endswith('.whl'):
                url = pkg
            else:
                raise Exception('Unable to install package from URL that is not an archive')
        else:
            pypi_json_url = 'https://pypi.org/pypi/%s/json' % pkg
            json_dest = _download(pypi_json_url, deps_dir)
            with open(json_dest, 'rb') as f:
                pkg_info = json.loads(f.read().decode('utf-8'))
            if os.path.exists(json_dest):
                os.remove(json_dest)

            if p['type'] == '==':
                if p['ver'] not in pkg_info['releases']:
                    raise Exception('Unable to find version %s of %s' % (p['ver'], pkg))
                url = _locate_suitable_download(pkg_info['releases'][p['ver']])
                if not url:
                    raise Exception('Unable to find a compatible download of %s == %s' % (pkg, p['ver']))
            else:
                p_ver_tup = _tuple_from_ver(p['ver'])
                for ver_str, ver_tup in reversed(_sort_pep440_versions(pkg_info['releases'], False)):
                    if p['type'] == '>=' and ver_tup < p_ver_tup:
                        break
                    url = _locate_suitable_download(pkg_info['releases'][ver_str])
                    if url:
                        break
                if not url:
                    if p['type'] == '>=':
                        raise Exception('Unable to find a compatible download of %s >= %s' % (pkg, p['ver']))
                    else:
                        raise Exception('Unable to find a compatible download of %s' % pkg)

        local_path = _download(url, deps_dir)

        _extract_package(deps_dir, local_path, pkg_sub_dir)

        os.remove(local_path)


def _parse_requires(path):
    """
    Does basic parsing of pip requirements files, to allow for
    using something other than Python to do actual TLS requests

    :param path:
        A path to a requirements file

    :return:
        A list of dict objects containing the keys:
         - 'type' ('any', 'url', '==', '>=')
         - 'pkg'
         - 'ver' (if 'type' == '==' or 'type' == '>=')
    """

    python_version = '.'.join(map(str_cls, sys.version_info[0:2]))
    sys_platform = sys.platform

    packages = []

    with open(path, 'rb') as f:
        contents = f.read().decode('utf-8')

    for line in re.split(r'\r?\n', contents):
        line = line.strip()
        if not len(line):
            continue
        if re.match(r'^\s*#', line):
            continue
        if ';' in line:
            package, cond = line.split(';', 1)
            package = package.strip()
            cond = cond.strip()
            cond = cond.replace('sys_platform', repr(sys_platform))
            cond = re.sub(
                r'[\'"]'
                r'(\d+(?:\.\d+)*)'
                r'([-._]?(?:alpha|a|beta|b|preview|pre|c|rc)\.?\d*)?'
                r'(-\d+|(?:[-._]?(?:rev|r|post)\.?\d*))?'
                r'([-._]?dev\.?\d*)?'
                r'[\'"]',
                r'_tuple_from_ver(\g<0>)',
                cond
            )
            cond = cond.replace('python_version', '_tuple_from_ver(%r)' % python_version)
            if not eval(cond):
                continue
        else:
            package = line.strip()

        if re.match(r'^\s*-r\s*', package):
            sub_req_file = re.sub(r'^\s*-r\s*', '', package)
            sub_req_file = os.path.abspath(os.path.join(os.path.dirname(path), sub_req_file))
            packages.extend(_parse_requires(sub_req_file))
            continue

        if re.match(r'https?://', package):
            packages.append({'type': 'url', 'pkg': package})
            continue

        if '>=' in package:
            parts = package.split('>=')
            package = parts[0].strip()
            ver = parts[1].strip()
            packages.append({'type': '>=', 'pkg': package, 'ver': ver})
            continue

        if '==' in package:
            parts = package.split('==')
            package = parts[0].strip()
            ver = parts[1].strip()
            packages.append({'type': '==', 'pkg': package, 'ver': ver})
            continue

        if re.search(r'[^ a-zA-Z0-9\-]', package):
            raise Exception('Unsupported requirements format version constraint: %s' % package)

        packages.append({'type': 'any', 'pkg': package})

    return packages


def _execute(params, cwd, retry=None, env=None):
    """
    Executes a subprocess

    :param params:
        A list of the executable and arguments to pass to it

    :param cwd:
        The working directory to execute the command in

    :param retry:
        If this string is present in stderr, retry the operation

    :return:
        A 2-element tuple of (stdout, stderr)
    """

    proc = subprocess.Popen(
        params,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env
    )
    stdout, stderr = proc.communicate()
    code = proc.wait()
    if code != 0:
        if retry and retry in stderr.decode('utf-8'):
            return _execute(params, cwd)
        e = OSError('subprocess exit code for "%s" was %d: %s' % (' '.join(params), code, stderr))
        e.stdout = stdout
        e.stderr = stderr
        raise e
    return (stdout, stderr)
