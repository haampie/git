#include "git-compat-util.h"
#include "config.h"
#include "dir.h"
#include "environment.h"
#include "ewah/ewok.h"
#include "fsmonitor.h"
#include "fsmonitor-ipc.h"
#include "name-hash.h"
#include "run-command.h"
#include "strbuf.h"
#include "trace2.h"

#define INDEX_EXTENSION_VERSION1	(1)
#define INDEX_EXTENSION_VERSION2	(2)
#define HOOK_INTERFACE_VERSION1		(1)
#define HOOK_INTERFACE_VERSION2		(2)

struct trace_key trace_fsmonitor = TRACE_KEY_INIT(FSMONITOR);

static void assert_index_minimum(struct index_state *istate, size_t pos)
{
	if (pos > istate->cache_nr)
		BUG("fsmonitor_dirty has more entries than the index (%"PRIuMAX" > %u)",
		    (uintmax_t)pos, istate->cache_nr);
}

static void fsmonitor_ewah_callback(size_t pos, void *is)
{
	struct index_state *istate = (struct index_state *)is;
	struct cache_entry *ce;

	assert_index_minimum(istate, pos + 1);

	ce = istate->cache[pos];
	ce->ce_flags &= ~CE_FSMONITOR_VALID;
}

static int fsmonitor_hook_version(void)
{
	int hook_version;

	if (git_config_get_int("core.fsmonitorhookversion", &hook_version))
		return -1;

	if (hook_version == HOOK_INTERFACE_VERSION1 ||
	    hook_version == HOOK_INTERFACE_VERSION2)
		return hook_version;

	warning("Invalid hook version '%i' in core.fsmonitorhookversion. "
		"Must be 1 or 2.", hook_version);
	return -1;
}

int read_fsmonitor_extension(struct index_state *istate, const void *data,
	unsigned long sz)
{
	const char *index = data;
	uint32_t hdr_version;
	uint32_t ewah_size;
	struct ewah_bitmap *fsmonitor_dirty;
	int ret;
	uint64_t timestamp;
	struct strbuf last_update = STRBUF_INIT;

	if (sz < sizeof(uint32_t) + 1 + sizeof(uint32_t))
		return error("corrupt fsmonitor extension (too short)");

	hdr_version = get_be32(index);
	index += sizeof(uint32_t);
	if (hdr_version == INDEX_EXTENSION_VERSION1) {
		timestamp = get_be64(index);
		strbuf_addf(&last_update, "%"PRIu64"", timestamp);
		index += sizeof(uint64_t);
	} else if (hdr_version == INDEX_EXTENSION_VERSION2) {
		strbuf_addstr(&last_update, index);
		index += last_update.len + 1;
	} else {
		return error("bad fsmonitor version %d", hdr_version);
	}

	istate->fsmonitor_last_update = strbuf_detach(&last_update, NULL);

	ewah_size = get_be32(index);
	index += sizeof(uint32_t);

	fsmonitor_dirty = ewah_new();
	ret = ewah_read_mmap(fsmonitor_dirty, index, ewah_size);
	if (ret != ewah_size) {
		ewah_free(fsmonitor_dirty);
		return error("failed to parse ewah bitmap reading fsmonitor index extension");
	}
	istate->fsmonitor_dirty = fsmonitor_dirty;

	if (!istate->split_index)
		assert_index_minimum(istate, istate->fsmonitor_dirty->bit_size);

	trace2_data_string("index", NULL, "extension/fsmn/read/token",
			   istate->fsmonitor_last_update);
	trace_printf_key(&trace_fsmonitor,
			 "read fsmonitor extension successful '%s'",
			 istate->fsmonitor_last_update);
	return 0;
}

void fill_fsmonitor_bitmap(struct index_state *istate)
{
	unsigned int i, skipped = 0;
	istate->fsmonitor_dirty = ewah_new();
	for (i = 0; i < istate->cache_nr; i++) {
		if (istate->cache[i]->ce_flags & CE_REMOVE)
			skipped++;
		else if (!(istate->cache[i]->ce_flags & CE_FSMONITOR_VALID))
			ewah_set(istate->fsmonitor_dirty, i - skipped);
	}
}

void write_fsmonitor_extension(struct strbuf *sb, struct index_state *istate)
{
	uint32_t hdr_version;
	uint32_t ewah_start;
	uint32_t ewah_size = 0;
	int fixup = 0;

	if (!istate->split_index)
		assert_index_minimum(istate, istate->fsmonitor_dirty->bit_size);

	put_be32(&hdr_version, INDEX_EXTENSION_VERSION2);
	strbuf_add(sb, &hdr_version, sizeof(uint32_t));

	strbuf_addstr(sb, istate->fsmonitor_last_update);
	strbuf_addch(sb, 0); /* Want to keep a NUL */

	fixup = sb->len;
	strbuf_add(sb, &ewah_size, sizeof(uint32_t)); /* we'll fix this up later */

	ewah_start = sb->len;
	ewah_serialize_strbuf(istate->fsmonitor_dirty, sb);
	ewah_free(istate->fsmonitor_dirty);
	istate->fsmonitor_dirty = NULL;

	/* fix up size field */
	put_be32(&ewah_size, sb->len - ewah_start);
	memcpy(sb->buf + fixup, &ewah_size, sizeof(uint32_t));

	trace2_data_string("index", NULL, "extension/fsmn/write/token",
			   istate->fsmonitor_last_update);
	trace_printf_key(&trace_fsmonitor,
			 "write fsmonitor extension successful '%s'",
			 istate->fsmonitor_last_update);
}

/*
 * Call the query-fsmonitor hook passing the last update token of the saved results.
 */
static int query_fsmonitor_hook(struct repository *r,
				int version,
				const char *last_update,
				struct strbuf *query_result)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	int result;

	if (fsm_settings__get_mode(r) != FSMONITOR_MODE_HOOK)
		return -1;

	strvec_push(&cp.args, fsm_settings__get_hook_path(r));
	strvec_pushf(&cp.args, "%d", version);
	strvec_pushf(&cp.args, "%s", last_update);
	cp.use_shell = 1;
	cp.dir = get_git_work_tree();

	trace2_region_enter("fsm_hook", "query", NULL);

	result = capture_command(&cp, query_result, 1024);

	if (result)
		trace2_data_intmax("fsm_hook", NULL, "query/failed", result);
	else
		trace2_data_intmax("fsm_hook", NULL, "query/response-length",
				   query_result->len);

	trace2_region_leave("fsm_hook", "query", NULL);

	return result;
}

static int fsmonitor_refresh_callback_slash(
	struct index_state *istate, const char *name, int len, int pos);

/*
 * Invalidate the untracked cache for the given pathname.  Copy the
 * buffer to a proper null-terminated string (since the untracked
 * cache code does not use (buf, len) style argument).  Also strip any
 * trailing slash.
 */
static void my_invalidate_untracked_cache(
	struct index_state *istate, const char *name, int len)
{
	struct strbuf work_path = STRBUF_INIT;

	if (!len)
		return;

	if (name[len-1] == '/')
		len--;

	strbuf_add(&work_path, name, len);
	untracked_cache_invalidate_path(istate, work_path.buf, 0);
	strbuf_release(&work_path);
}

/*
 * Invalidate the FSM bit on this CE.  This is like mark_fsmonitor_invalid()
 * but we've already handled the untracked-cache and I want a different
 * trace message.
 */
static void my_invalidate_ce_fsm(struct cache_entry *ce)
{
	if (ce->ce_flags & CE_FSMONITOR_VALID)
		trace_printf_key(&trace_fsmonitor,
				 "fsmonitor_refresh_cb_invalidate '%s'",
				 ce->name);
	ce->ce_flags &= ~CE_FSMONITOR_VALID;
}

/*
 * Use the name-hash to lookup the pathname.
 *
 * Returns the number of cache-entries that we invalidated.
 */
static int my_callback_name_hash(
	struct index_state *istate, const char *name, int len)
{
	struct cache_entry *ce = NULL;

	ce = index_file_exists(istate, name, len, 1);
	if (!ce)
		return 0;

	/*
	 * The index contains a case-insensitive match for the pathname.
	 * This could either be a regular file or a sparse-index directory.
	 *
	 * We should not have seen FSEvents for a sparse-index directory,
	 * but we handle it just in case.
	 *
	 * Either way, we know that there are not any cache-entries for
	 * children inside the cone of the directory, so we don't need to
	 * do the usual scan.
	 */
	trace_printf_key(&trace_fsmonitor,
			 "fsmonitor_refresh_callback map '%s' '%s'",
			 name, ce->name);

	my_invalidate_untracked_cache(istate, ce->name, ce->ce_namelen);

	my_invalidate_ce_fsm(ce);
	return 1;
}

/*
 * Use the directory name-hash to find the correct-case spelling
 * of the directory.  Use the canonical spelling to invalidate all
 * of the cache-entries within the matching cone.
 *
 * The pathname MUST NOT have a trailing slash.
 *
 * Returns the number of cache-entries that we invalidated.
 */
static int my_callback_dir_name_hash(
	struct index_state *istate, const char *name, int len)
{
	struct strbuf canonical_path = STRBUF_INIT;
	int pos;
	int nr_in_cone;

	if (!index_dir_exists2(istate, name, len, &canonical_path))
		return 0; /* name is untracked */
	if (!memcmp(name, canonical_path.buf, len)) {
		strbuf_release(&canonical_path);
		return 0; /* should not happen */
	}

	trace_printf_key(&trace_fsmonitor,
			 "fsmonitor_refresh_callback map '%s' '%s'",
			 name, canonical_path.buf);

	/*
	 * The directory name-hash only tells us the corrected
	 * spelling of the prefix.  We have to use this canonical
	 * path to do a lookup in the cache-entry array so that we
	 * we repeat the original search using the case-corrected
	 * spelling.
	 */
	strbuf_addch(&canonical_path, '/');
	pos = index_name_pos(istate, canonical_path.buf,
			     canonical_path.len);
	nr_in_cone = fsmonitor_refresh_callback_slash(
		istate, canonical_path.buf, canonical_path.len, pos);
	strbuf_release(&canonical_path);
	return nr_in_cone;
}

/*
 * The daemon sent an observed pathname without a trailing slash.
 * (This is the normal case.)  We do not know if it is a tracked or
 * untracked file, a sparse-directory, or a populated directory (on a
 * platform such as Windows where FSEvents are not qualified).
 *
 * The pathname contains the observed case reported by the FS. We
 * do not know it is case-correct or -incorrect.
 *
 * Assume it is case-correct and try an exact match.
 *
 * Return the number of cache-entries that we invalidated.
 */
static int fsmonitor_refresh_callback_unqualified(
	struct index_state *istate, const char *name, int len, int pos)
{
	my_invalidate_untracked_cache(istate, name, len);

	if (pos >= 0) {
		/*
		 * An exact match on a tracked file. We assume that we
		 * do not need to scan forward for a sparse-directory
		 * cache-entry with the same pathname, nor for a cone
		 * at that directory. (That is, assume no D/F conflicts.)
		 */
		my_invalidate_ce_fsm(istate->cache[pos]);
		return 1;
	} else {
		int nr_in_cone;
		struct strbuf work_path = STRBUF_INIT;

		/*
		 * The negative "pos" gives us the suggested insertion
		 * point for the pathname (without the trailing slash).
		 * We need to see if there is a directory with that
		 * prefix, but there can be lots of pathnames between
		 * "foo" and "foo/" like "foo-" or "foo-bar", so we
		 * don't want to do our own scan.
		 */
		strbuf_add(&work_path, name, len);
		strbuf_addch(&work_path, '/');
		pos = index_name_pos(istate, work_path.buf, work_path.len);
		nr_in_cone = fsmonitor_refresh_callback_slash(
			istate, work_path.buf, work_path.len, pos);
		strbuf_release(&work_path);
		return nr_in_cone;
	}
}

/*
 * On a case-insensitive FS, use the name-hash to map the case of
 * the observed path to the canonical case expected by the index.
 *
 * The given pathname DOES NOT include the trailing slash.
 *
 * Return the number of cache-entries that we invalidated.
 */
static int fsmonitor_refresh_callback_unqualified_icase(
	struct index_state *istate, const char *name, int len)
{
	int nr_in_cone;

	/*
	 * Look for a case-incorrect match for this non-directory
	 * pathname.
	 */
	nr_in_cone = my_callback_name_hash(istate, name, len);
	if (nr_in_cone)
		return nr_in_cone;

	/*
	 * Try the directory name-hash and see if there is a
	 * case-incorrect directory with this pathanme.
	 * (len) because we don't have a trailing slash.
	 */
	nr_in_cone = my_callback_dir_name_hash(istate, name, len);
	return nr_in_cone;
}

/*
 * The daemon can decorate directory events, such as a move or rename,
 * by adding a trailing slash to the observed name.  Use this to
 * explicitly invalidate the entire cone under that directory.
 *
 * The daemon can only reliably do that if the OS FSEvent contains
 * sufficient information in the event.
 *
 * macOS FSEvents have enough information.
 *
 * Other platforms may or may not be able to do it (and it might
 * depend on the type of event (for example, a daemon could lstat() an
 * observed pathname after a rename, but not after a delete)).
 *
 * If we find an exact match in the index for a path with a trailing
 * slash, it means that we matched a sparse-index directory in a
 * cone-mode sparse-checkout (since that's the only time we have
 * directories in the index).  We should never see this in practice
 * (because sparse directories should not be present and therefore
 * not generating FS events).  Either way, we can treat them in the
 * same way and just invalidate the cache-entry and the untracked
 * cache (and in this case, the forward cache-entry scan won't find
 * anything and it doesn't hurt to let it run).
 *
 * Return the number of cache-entries that we invalidated.  We will
 * use this later to determine if we need to attempt a second
 * case-insensitive search.  That is, if a observed-case search yields
 * any results, we assume the prefix is case-correct.  If there are
 * no matches, we still don't know if the observed path is simply
 * untracked or case-incorrect.
 */
static int fsmonitor_refresh_callback_slash(
	struct index_state *istate, const char *name, int len, int pos)
{
	int i;
	int nr_in_cone = 0;

	my_invalidate_untracked_cache(istate, name, len);

	if (pos < 0)
		pos = -pos - 1;

	/* Mark all entries for the folder invalid */
	for (i = pos; i < istate->cache_nr; i++) {
		if (!starts_with(istate->cache[i]->name, name))
			break;
		my_invalidate_ce_fsm(istate->cache[i]);
		nr_in_cone++;
	}

	return nr_in_cone;
}

/*
 * On a case-insensitive FS, use the name-hash and directory name-hash
 * to map the case of the observed path to the canonical case expected
 * by the index.
 *
 * The given pathname includes the trailing slash.
 *
 * Return the number of cache-entries that we invalidated.
 */
static int fsmonitor_refresh_callback_slash_icase(
	struct index_state *istate, const char *name, int len)
{
	int nr_in_cone;

	/*
	 * Look for a case-incorrect sparse-index directory.
	 */
	nr_in_cone = my_callback_name_hash(istate, name, len);
	if (nr_in_cone)
		return nr_in_cone;

	/*
	 * (len-1) because we do not include the trailing slash in the
	 * pathname.
	 */
	nr_in_cone = my_callback_dir_name_hash(istate, name, len-1);
	return nr_in_cone;
}

static void fsmonitor_refresh_callback(struct index_state *istate, char *name)
{
	int len = strlen(name);
	int pos = index_name_pos(istate, name, len);
	int nr_in_cone;


	trace_printf_key(&trace_fsmonitor,
			 "fsmonitor_refresh_callback '%s' (pos %d)",
			 name, pos);

	if (name[len - 1] == '/') {
		nr_in_cone = fsmonitor_refresh_callback_slash(istate, name, len, pos);
		if (ignore_case && !nr_in_cone)
			fsmonitor_refresh_callback_slash_icase(istate, name, len);
	} else {
		nr_in_cone = fsmonitor_refresh_callback_unqualified(istate, name, len, pos);
		if (ignore_case && !nr_in_cone)
			fsmonitor_refresh_callback_unqualified_icase(istate, name, len);
	}
}

/*
 * The number of pathnames that we need to receive from FSMonitor
 * before we force the index to be updated.
 *
 * Note that any pathname within the set of received paths MAY cause
 * cache-entry or istate flag bits to be updated and thus cause the
 * index to be updated on disk.
 *
 * However, the response may contain many paths (such as ignored
 * paths) that will not update any flag bits.  And thus not force the
 * index to be updated.  (This is fine and normal.)  It also means
 * that the token will not be updated in the FSMonitor index
 * extension.  So the next Git command will find the same token in the
 * index, make the same token-relative request, and receive the same
 * response (plus any newly changed paths).  If this response is large
 * (and continues to grow), performance could be impacted.
 *
 * For example, if the user runs a build and it writes 100K object
 * files but doesn't modify any source files, the index would not need
 * to be updated.  The FSMonitor response (after the build and
 * relative to a pre-build token) might be 5MB.  Each subsequent Git
 * command will receive that same 100K/5MB response until something
 * causes the index to be updated.  And `refresh_fsmonitor()` will
 * have to iterate over those 100K paths each time.
 *
 * Performance could be improved if we optionally force update the
 * index after a very large response and get an updated token into
 * the FSMonitor index extension.  This should allow subsequent
 * commands to get smaller and more current responses.
 *
 * The value chosen here does not need to be precise.  The index
 * will be updated automatically the first time the user touches
 * a tracked file and causes a command like `git status` to
 * update an mtime to be updated and/or set a flag bit.
 */
static int fsmonitor_force_update_threshold = 100;

void refresh_fsmonitor(struct index_state *istate)
{
	static int warn_once = 0;
	struct strbuf query_result = STRBUF_INIT;
	int query_success = 0, hook_version = -1;
	size_t bol = 0; /* beginning of line */
	uint64_t last_update;
	struct strbuf last_update_token = STRBUF_INIT;
	char *buf;
	unsigned int i;
	int is_trivial = 0;
	struct repository *r = istate->repo;
	enum fsmonitor_mode fsm_mode = fsm_settings__get_mode(r);
	enum fsmonitor_reason reason = fsm_settings__get_reason(r);

	if (!warn_once && reason > FSMONITOR_REASON_OK) {
		char *msg = fsm_settings__get_incompatible_msg(r, reason);
		warn_once = 1;
		warning("%s", msg);
		free(msg);
	}

	if (fsm_mode <= FSMONITOR_MODE_DISABLED ||
	    istate->fsmonitor_has_run_once)
		return;

	istate->fsmonitor_has_run_once = 1;

	trace_printf_key(&trace_fsmonitor, "refresh fsmonitor");

	if (fsm_mode == FSMONITOR_MODE_IPC) {
		query_success = !fsmonitor_ipc__send_query(
			istate->fsmonitor_last_update ?
			istate->fsmonitor_last_update : "builtin:fake",
			&query_result);
		if (query_success) {
			/*
			 * The response contains a series of nul terminated
			 * strings.  The first is the new token.
			 *
			 * Use `char *buf` as an interlude to trick the CI
			 * static analysis to let us use `strbuf_addstr()`
			 * here (and only copy the token) rather than
			 * `strbuf_addbuf()`.
			 */
			buf = query_result.buf;
			strbuf_addstr(&last_update_token, buf);
			bol = last_update_token.len + 1;
			is_trivial = query_result.buf[bol] == '/';
			if (is_trivial)
				trace2_data_intmax("fsm_client", NULL,
						   "query/trivial-response", 1);
		} else {
			/*
			 * The builtin daemon is not available on this
			 * platform -OR- we failed to get a response.
			 *
			 * Generate a fake token (rather than a V1
			 * timestamp) for the index extension.  (If
			 * they switch back to the hook API, we don't
			 * want ambiguous state.)
			 */
			strbuf_addstr(&last_update_token, "builtin:fake");
		}

		goto apply_results;
	}

	assert(fsm_mode == FSMONITOR_MODE_HOOK);

	hook_version = fsmonitor_hook_version();

	/*
	 * This could be racy so save the date/time now and query_fsmonitor_hook
	 * should be inclusive to ensure we don't miss potential changes.
	 */
	last_update = getnanotime();
	if (hook_version == HOOK_INTERFACE_VERSION1)
		strbuf_addf(&last_update_token, "%"PRIu64"", last_update);

	/*
	 * If we have a last update token, call query_fsmonitor_hook for the set of
	 * changes since that token, else assume everything is possibly dirty
	 * and check it all.
	 */
	if (istate->fsmonitor_last_update) {
		if (hook_version == -1 || hook_version == HOOK_INTERFACE_VERSION2) {
			query_success = !query_fsmonitor_hook(
				r, HOOK_INTERFACE_VERSION2,
				istate->fsmonitor_last_update, &query_result);

			if (query_success) {
				if (hook_version < 0)
					hook_version = HOOK_INTERFACE_VERSION2;

				/*
				 * First entry will be the last update token
				 * Need to use a char * variable because static
				 * analysis was suggesting to use strbuf_addbuf
				 * but we don't want to copy the entire strbuf
				 * only the chars up to the first NUL
				 */
				buf = query_result.buf;
				strbuf_addstr(&last_update_token, buf);
				if (!last_update_token.len) {
					warning("Empty last update token.");
					query_success = 0;
				} else {
					bol = last_update_token.len + 1;
					is_trivial = query_result.buf[bol] == '/';
				}
			} else if (hook_version < 0) {
				hook_version = HOOK_INTERFACE_VERSION1;
				if (!last_update_token.len)
					strbuf_addf(&last_update_token, "%"PRIu64"", last_update);
			}
		}

		if (hook_version == HOOK_INTERFACE_VERSION1) {
			query_success = !query_fsmonitor_hook(
				r, HOOK_INTERFACE_VERSION1,
				istate->fsmonitor_last_update, &query_result);
			if (query_success)
				is_trivial = query_result.buf[0] == '/';
		}

		if (is_trivial)
			trace2_data_intmax("fsm_hook", NULL,
					   "query/trivial-response", 1);

		trace_performance_since(last_update, "fsmonitor process '%s'",
					fsm_settings__get_hook_path(r));
		trace_printf_key(&trace_fsmonitor,
				 "fsmonitor process '%s' returned %s",
				 fsm_settings__get_hook_path(r),
				 query_success ? "success" : "failure");
	}

apply_results:
	/*
	 * The response from FSMonitor (excluding the header token) is
	 * either:
	 *
	 * [a] a (possibly empty) list of NUL delimited relative
	 *     pathnames of changed paths.  This list can contain
	 *     files and directories.  Directories have a trailing
	 *     slash.
	 *
	 * [b] a single '/' to indicate the provider had no
	 *     information and that we should consider everything
	 *     invalid.  We call this a trivial response.
	 */
	trace2_region_enter("fsmonitor", "apply_results", istate->repo);

	if (query_success && !is_trivial) {
		/*
		 * Mark all pathnames returned by the monitor as dirty.
		 *
		 * This updates both the cache-entries and the untracked-cache.
		 */
		int count = 0;

		buf = query_result.buf;
		for (i = bol; i < query_result.len; i++) {
			if (buf[i] != '\0')
				continue;
			fsmonitor_refresh_callback(istate, buf + bol);
			bol = i + 1;
			count++;
		}
		if (bol < query_result.len) {
			fsmonitor_refresh_callback(istate, buf + bol);
			count++;
		}

		/* Now mark the untracked cache for fsmonitor usage */
		if (istate->untracked)
			istate->untracked->use_fsmonitor = 1;

		if (count > fsmonitor_force_update_threshold)
			istate->cache_changed |= FSMONITOR_CHANGED;

		trace2_data_intmax("fsmonitor", istate->repo, "apply_count",
				   count);

	} else {
		/*
		 * We failed to get a response or received a trivial response,
		 * so invalidate everything.
		 *
		 * We only want to run the post index changed hook if
		 * we've actually changed entries, so keep track if we
		 * actually changed entries or not.
		 */
		int is_cache_changed = 0;

		for (i = 0; i < istate->cache_nr; i++) {
			if (istate->cache[i]->ce_flags & CE_FSMONITOR_VALID) {
				is_cache_changed = 1;
				istate->cache[i]->ce_flags &= ~CE_FSMONITOR_VALID;
			}
		}

		/*
		 * If we're going to check every file, ensure we save
		 * the results.
		 */
		if (is_cache_changed)
			istate->cache_changed |= FSMONITOR_CHANGED;

		if (istate->untracked)
			istate->untracked->use_fsmonitor = 0;
	}
	trace2_region_leave("fsmonitor", "apply_results", istate->repo);

	strbuf_release(&query_result);

	/* Now that we've updated istate, save the last_update_token */
	FREE_AND_NULL(istate->fsmonitor_last_update);
	istate->fsmonitor_last_update = strbuf_detach(&last_update_token, NULL);
}

/*
 * The caller wants to turn on FSMonitor.  And when the caller writes
 * the index to disk, a FSMonitor extension should be included.  This
 * requires that `istate->fsmonitor_last_update` not be NULL.  But we
 * have not actually talked to a FSMonitor process yet, so we don't
 * have an initial value for this field.
 *
 * For a protocol V1 FSMonitor process, this field is a formatted
 * "nanoseconds since epoch" field.  However, for a protocol V2
 * FSMonitor process, this field is an opaque token.
 *
 * Historically, `add_fsmonitor()` has initialized this field to the
 * current time for protocol V1 processes.  There are lots of race
 * conditions here, but that code has shipped...
 *
 * The only true solution is to use a V2 FSMonitor and get a current
 * or default token value (that it understands), but we cannot do that
 * until we have actually talked to an instance of the FSMonitor process
 * (but the protocol requires that we send a token first...).
 *
 * For simplicity, just initialize like we have a V1 process and require
 * that V2 processes adapt.
 */
static void initialize_fsmonitor_last_update(struct index_state *istate)
{
	struct strbuf last_update = STRBUF_INIT;

	strbuf_addf(&last_update, "%"PRIu64"", getnanotime());
	istate->fsmonitor_last_update = strbuf_detach(&last_update, NULL);
}

void add_fsmonitor(struct index_state *istate)
{
	unsigned int i;

	if (!istate->fsmonitor_last_update) {
		trace_printf_key(&trace_fsmonitor, "add fsmonitor");
		istate->cache_changed |= FSMONITOR_CHANGED;
		initialize_fsmonitor_last_update(istate);

		/* reset the fsmonitor state */
		for (i = 0; i < istate->cache_nr; i++)
			istate->cache[i]->ce_flags &= ~CE_FSMONITOR_VALID;

		/* reset the untracked cache */
		if (istate->untracked) {
			add_untracked_cache(istate);
			istate->untracked->use_fsmonitor = 1;
		}

		/* Update the fsmonitor state */
		refresh_fsmonitor(istate);
	}
}

void remove_fsmonitor(struct index_state *istate)
{
	if (istate->fsmonitor_last_update) {
		trace_printf_key(&trace_fsmonitor, "remove fsmonitor");
		istate->cache_changed |= FSMONITOR_CHANGED;
		FREE_AND_NULL(istate->fsmonitor_last_update);
	}
}

void tweak_fsmonitor(struct index_state *istate)
{
	unsigned int i;
	int fsmonitor_enabled = (fsm_settings__get_mode(istate->repo)
				 > FSMONITOR_MODE_DISABLED);

	if (istate->fsmonitor_dirty) {
		if (fsmonitor_enabled) {
			/* Mark all entries valid */
			for (i = 0; i < istate->cache_nr; i++) {
				if (S_ISGITLINK(istate->cache[i]->ce_mode))
					continue;
				istate->cache[i]->ce_flags |= CE_FSMONITOR_VALID;
			}

			/* Mark all previously saved entries as dirty */
			assert_index_minimum(istate, istate->fsmonitor_dirty->bit_size);
			ewah_each_bit(istate->fsmonitor_dirty, fsmonitor_ewah_callback, istate);

			refresh_fsmonitor(istate);
		}

		ewah_free(istate->fsmonitor_dirty);
		istate->fsmonitor_dirty = NULL;
	}

	if (fsmonitor_enabled)
		add_fsmonitor(istate);
	else
		remove_fsmonitor(istate);
}
