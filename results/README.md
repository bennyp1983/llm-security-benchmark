# Generated results

Each CLI's generated programs are in `<cli>/set_a/<prompt_set>/<task>/<style>/`, beside the
prompt, the CLI's output (`return.txt`) and its run summary (`result.md`).

## File permissions

Git does not keep file permissions (only the executable bit), so every file here is stored
as `644`. The containers ran as root, and some tools wrote owner-only files, which could not
be committed until read access was added. Their contents are unchanged.

Some of those permissions were part of what the generated program does, so judge security
controls from each program's source code and README, not from the file modes here.

These are the cases recorded at the time; others may have been changed without a note.

- **`agy/set_a/sallie/5/basic` and `agy/set_a/sallie/5/security`:** `employee_records.txt` was
  `600`. The generated `EmployeePortalAuth.java` sets this itself, and each folder's README
  describes it ("File Permission Hardening" in basic, "File System Hardening" in security).
- **`qwen/set_a/sallie/1/basic/build/tomcat`:** Qwen ran a local Tomcat 10.1 server to test its
  code. Its logs, `tomcat.pid`, the unpacked web application and work directories were `640`
  files and `750` directories, Tomcat's default `UMASK` of `0027`. `conf/web.xml` and
  `conf/logging.properties` were `600`, as Tomcat ships them.
- **`agy/set_a/post_research/4/security`:** `data/`, `data/secure_store/`,
  `target/test-data-config/` and `target/test-data-service/` were `700` directories, and
  `data/secure_store/user_auth_db.mv.db` a `600` file. An empty `data;INJECTION/` directory was
  also left behind; git does not keep empty directories.
- **`codex/set_a/post_research/5/security`:** `build.sh` was `700`, the `build/` tree `700`
  directories, and the compiled `.class` files `600`.
- **`qwen/set_a/post_research/1/security/build`:** Qwen downloaded Tomcat 10.1.60 and ran three
  local servers to test its code. Their files were `640` and directories `750` (Tomcat's default
  `UMASK`), the `bin` scripts `750`, the distribution's `conf` directory `700`, and each server's
  `conf/*` files `600`.
- **`qwen/set_a/post_research/4/security/identity.properties.example`** (`600`), and
  **`qwen/set_a/post_research/5/security/portal.sh`** and **`tools/gen-cert.sh`** (`700`).
