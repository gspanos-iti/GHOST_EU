# Readme

Source code of GHOST project, supported by the EU Framework Programme for Research and Innovation Horizon 2020
(specifically in the topic DS-02-2016, under Grant Agreement number GA-740923).

## Conventions

The name of the directories/files MUST use underscore naming style (e.g. `some_dir/some_file.py`) if not required
otherwise (the coding style of some of the used programming languages requires a certain naming style).

Binary files MUST NOT be added to the Git repository, instead add them to [Colabora](https://colabora.televes.com) and
insert references (links) to them in the `README.md`, `INSTALL.md` or other documentation file.

Markdown files MUST use the [GitHub format](https://github.github.com/gfm).
There are several Markdown flavours, but this one is supported by GitLab).
Also, the files MUST have the `*.md` extension and the line length MUST not exceed 120 characters.

Each module directory MUST contain the following documentation files:
- `README.md`
  - short description of the directory content
  - directory structure description
  - "how to" for libraries, modules, etc.
  - other relevant information
- `INSTALL.md`
  - module dependencies including version (minimum, maximum) and licenses
  - dependencies must be split in 2:
      - build dependencies (only for programming languages which are compilable: C, Java)
      - runtime dependencies
  - module configuration
  - "how to" start/stop the module
  - other relevant information

A module MAY contain a `debian` directory which contains debian related resources:
* init.d script to run the the module as a daemon
* required files to build Debian packages (see [Debian Maintenance Guide](https://www.debian.org/doc/manuals/maint-guide))

All module SHOULD support the `--help` option if possible.
All module being executed as processes SHOULD be able to run in background as Linux daemons.
Module configuration MUST be stored in a file (`*.ini` or `*.xml`) whose path is passed as an argument when the process
is started
(usually, module configuration is stored in `/etc` at deployment time).

### C

Headers files use `*.h` extension.
Source files use `*.c` extension.

The structure of a GHOST module implemented in C (asume `<name>` is the name of the module):
- `<git_root>/<name>` - the root directory of the module (stored in the root of the Git repository)
- `<git_root>/<name>/src` - all C source files (`*.c` and `*.h` files) are stored under this directory.
- `<git_root>/<name>/cmake` - CMake related files.
- `<git_root>/<name>/debian` - see above
- `<git_root>/<name>/README.md` - see above
- `<git_root>/<name>/INSTALL.md` - see above

### Java

Coding style to be used for Java: https://google.github.io/styleguide/javaguide.html.
The code must be implemented using Java 8.
The toolchain must be Maven or Gradle.
The proper directory layout must be used:
- for Maven: https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html (we will
use README.md instead of README.tx)
- for Gradle: https://docs.gradle.org/current/userguide/java_plugin.html

All Java code MUST be part of the `eu.ghost_iot` package or one of their subpackages.
It is a common practice to use the reverse domain (`ghost-iot.eu` is the project domain) as package name.
Also, each module should store its code in his own subpackage (e.g. module `abcd` should use the `eu.ghost_iot.abcd`
package name).

### Python

Python code MUST follow [PEP-0008](https://www.python.org/dev/peps/pep-0008/).

All imports MUST use absolute path (do NOT use relative paths).

The structure of a GHOST module implemented in Python (asume `<name>` is the name of the module):
- `<git_root>/<name>` - the root directory of the module (stored in the root of the Git repository)
- `<git_root>/<name>/src` - all Python source files are stored under this directory. This path MUST be added at runtime
in the `$PYTHONPATH` variable so other modules can import them using absolute path.
- `<git_root>/<name>/src/ghost_<name>` - Directory used to group all module sources (except the main script) in the
`ghost_<name>` package. This helps avoiding name collisions. It MUST contain the `__init__.py` file.
- `<git_root>/<name>/src/ghost-<name>.py` - the main module script. It has the executable bit set and the shebang
properly set.
By default the process is started in foreground.
- `<git_root>/<name>/debian` - see above
- `<git_root>/<name>/README.md` - see above
- `<git_root>/<name>/INSTALL.md` - see above

### SQL

For SQL code the following conding style will be used: http://www.sqlstyle.guide/
