/*-
 * Copyright (c) 2015 Michal Ratajsky <michal@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/usr.sbin/makefs/mtree.c 264186 2014-04-06 02:57:49Z marcel $");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <grp.h>
#include <mtree.h>
#include <mtree_file.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "makefs.h"

#define IS_DOT(nm)	((nm)[0] == '.' && (nm)[1] == '\0')

#define STAT_KEYWORDS	(MTREE_KEYWORD_TYPE | MTREE_KEYWORD_UNAME |	\
			 MTREE_KEYWORD_UID  | MTREE_KEYWORD_GNAME |	\
			 MTREE_KEYWORD_GID  | MTREE_KEYWORD_NLINK |	\
			 MTREE_KEYWORD_MODE | MTREE_KEYWORD_FLAGS |	\
			 MTREE_KEYWORD_SIZE | MTREE_KEYWORD_TIME)
struct rbtree rbtree;
struct rbnode {
	RB_ENTRY(rbnode) rbentry;
	fsnode *node;
};

static int errors;
#define MTREE_ERROR(format, ...)			\
	do {						\
		fprintf(stderr, format, __VA_ARGS__);	\
		fprintf(stderr, "\n");			\
		errors++;				\
	} while (0);

static int
rbnodecmp(struct rbnode *a, struct rbnode *b)
{
	int ret;

	ret = strcmp(a->node->path, b->node->path);
	if (ret == 0)
		ret = strcmp(a->node->name, b->node->name);
	return (ret);
}

RB_HEAD(rbtree, rbnode) rbhead = RB_INITIALIZER(&rbhead);
RB_GENERATE_STATIC(rbtree, rbnode, rbentry, rbnodecmp);

static void
entry_to_stat(struct mtree_entry *entry, struct stat *st, uint64_t keywords)
{
	struct mtree_timespec *ts;

	/*
	 * Make sure to only work with keywords that are not only wanted,
	 * but also present in the spec entry.
	 */
	keywords &= mtree_entry_get_keywords(entry);

	if (keywords & MTREE_KEYWORD_TYPE) {
		mode_t type;

		switch (mtree_entry_get_type(entry)) {
		case MTREE_ENTRY_DIR:
			type = S_IFDIR;
			break;
		case MTREE_ENTRY_LINK:
			type = S_IFLNK;
			break;
		case MTREE_ENTRY_BLOCK:
			type = S_IFBLK;
			break;
		case MTREE_ENTRY_CHAR:
			type = S_IFCHR;
			break;
		case MTREE_ENTRY_FIFO:
			type = S_IFIFO;
			break;
		case MTREE_ENTRY_SOCKET:
			type = S_IFSOCK;
			break;
		case MTREE_ENTRY_FILE:
		default:
			/*
			 * By default treat entries as files.
			 */
			type = S_IFREG;
			break;
		}
		st->st_mode &= ~S_IFMT;
		st->st_mode |= type;
	}

	if (keywords & (MTREE_KEYWORD_GID | MTREE_KEYWORD_GNAME)) {
		if ((keywords & MTREE_KEYWORD_GID) == 0) {
			if (gid_from_group(mtree_entry_get_gname(entry),
			    &st->st_gid) == -1)
				MTREE_ERROR("`%s': unknown group in specfile: %s",
				    mtree_entry_get_path(entry),
				    mtree_entry_get_gname(entry));
		} else
			st->st_gid = mtree_entry_get_gid(entry);
	}

#if HAVE_STRUCT_STAT_ST_FLAGS
	if (keywords & MTREE_KEYWORD_FLAGS) {
		char *s;
		const char *value;
		u_long flags;

		value = mtree_entry_get_flags(entry);
		if (strcmp(value, "none") == 0) {
			/*
			 * libmtree uses the string "none" for no flags.
			 */
			st->st_flags = 0;
		} else {
			s = strdup(value);
			if (s == NULL);
				err(1, "Memory allocation error");
			if (strtofflags(&s, &flags, NULL) == 0)
				st->st_flags = (fflags_t)flags;
			else
				MTREE_ERROR("`%s': unknown flag in specfile: %s",
				    mtree_entry_get_path(entry),
				    s);
			free(s);
		}
	}
#endif
	if (keywords & (MTREE_KEYWORD_UID | MTREE_KEYWORD_UNAME)) {
		if ((keywords & MTREE_KEYWORD_UID) == 0) {
			if (uid_from_user(mtree_entry_get_uname(entry),
			    &st->st_uid) == -1)
				MTREE_ERROR("`%s': unknown user in specfile: %s",
				    mtree_entry_get_path(entry),
				    mtree_entry_get_uname(entry));
		} else
			st->st_uid = mtree_entry_get_uid(entry);
	}

	if (keywords & MTREE_KEYWORD_MODE) {
		st->st_mode &= ~ALLPERMS;
		st->st_mode |= mtree_entry_get_mode(entry);
	}
	if (keywords & MTREE_KEYWORD_NLINK)
		st->st_nlink = mtree_entry_get_nlink(entry);

	if (keywords & MTREE_KEYWORD_TIME) {
		ts = mtree_entry_get_time(entry);
		st->st_mtime = ts->tv_sec;
		st->st_atime = ts->tv_sec;
		st->st_ctime = ts->tv_sec;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
		st->st_mtimensec = ts->tv_nsec;
		st->st_atimensec = ts->tv_nsec;
		st->st_ctimensec = ts->tv_nsec;
#endif
	}
	if (keywords & MTREE_KEYWORD_SIZE)
		st->st_size = mtree_entry_get_size(entry);
}

static int
fill_node(fsnode *node, struct mtree_entry *entry, struct stat *st)
{
	struct stat sb;
	uint64_t keywords;

	keywords = mtree_entry_get_keywords(entry);

	if (S_ISLNK(st->st_mode) && keywords & MTREE_KEYWORD_LINK) {
		node->symlink = strdup(mtree_entry_get_link(entry));
		if (node->symlink == NULL)
			err(1, "Memory allocation error");
	}
	if (S_ISREG(st->st_mode)) {
		if (keywords & MTREE_KEYWORD_CONTENTS)
			node->contents =
			    strdup(mtree_entry_get_contents(entry));
		else
			node->contents =
			    strdup(mtree_entry_get_path(entry));
		if (node->contents == NULL)
			err(1, "Memory allocation error");
	} else if (keywords & MTREE_KEYWORD_CONTENTS)
		warnx("`%s': ignoring contents keyword: not a regular file",
		    mtree_entry_get_path(entry));

	if (keywords & MTREE_KEYWORD_OPTIONAL)
		node->flags |= FSNODE_F_OPTIONAL;
	if (node->contents == NULL)
		return (0);

	if (stat(node->contents, &sb) != 0) {
		MTREE_ERROR("`%s': contents file `%s' not found",
		    mtree_entry_get_path(entry),
		    node->contents);
		return (-1);
	}
	/*
         * Check for hardlinks. If the contents key is used, then the check
         * will only trigger if the contents file is a link even if it is used
         * by more than one file.
	 */
	if (sb.st_nlink > 1) {
		fsinode *curino;

		node->inode->st.st_ino = sb.st_ino;
		node->inode->st.st_dev = sb.st_dev;
		curino = link_check(node->inode);
		if (curino != NULL) {
			free(node->inode);
			node->inode = curino;
			node->inode->nlink++;
		}
	}
	return (0);
}

static fsnode *
create_dirnode(const char *root, const char *path, const char *name)
{
	struct stat st;

	memset(&st, 0, sizeof(st));

	st.st_mode = S_IFDIR;
	return (create_fsnode(root, path, name, &st));
}

static fsnode *
rbnode_add(fsnode *root, const char *full_path, fsnode *node)
{
	struct rbnode find;
	struct rbnode *child;
	struct rbnode *item, *dot;
	char *name;
	char *end;
	const char *tmp;
	size_t len;
	char path[MAXPATHLEN + 1];
	int stop;

	tmp = full_path;
	len = strlen(tmp);
	if (len > MAXPATHLEN)
		errx(1, "Pathname too long.");
	end = stpcpy(path, tmp) - 1;

	/*
	 * Path in mtree_entry contains the full path including the file name,
	 * fsnode expect the path to be the dirname.
	 *
	 * If the entry contains ".", it is both the path and name.
	 */
	find.node = malloc(sizeof(struct rbnode));
	if (find.node == NULL)
		err(1, "Memory allocation error");

	stop = 0;
	child = NULL;
	for (;;) {
		while (*end != '/' && end != path)
			end--;
		if (end == path)
			break;
		name = end + 1;
		while (*end == '/' && end != path)
			end--;
		if (end == path && *end == '/')
			break;
		*(end + 1) = '\0';

		find.node->path = path;
		find.node->name = name;

		item = RB_FIND(rbtree, &rbhead, &find);
		if (item == NULL) {
			item = malloc(sizeof(struct rbnode));
			if (item == NULL)
				err(1, "Memory allocation error");
			if (child == NULL) {
				/*
				 * Child being NULL means that we have not yet
				 * started creating missing parent directories,
				 * so the entry just created is the requested
				 * mtree entry and we can assign remaining values
				 * to the entry's fsnode.
				 */
				item->node = node;
			} else
				item->node = create_dirnode(".", path, name);

			RB_INSERT(rbtree, &rbhead, item);
			if (IS_DOT(path)) {
				/*
				 * Add to the root level, this is done separately
				 * here as root level nodes have no parent and are
				 * not processed here.
				 */
				item->node->first = root->first;
				item->node->next  = root->next;
				root->next = item->node;
			}
		} else
			stop = 1;

		if (child != NULL) {
			child->node->parent = item->node;
			/*
			 * If a child is set, then the current item must be a
			 * directory, make sure it contains a "." item before
			 * adding the child.
			 */
			if (item->node->child == NULL) {
				dot = malloc(sizeof(struct rbnode));
				if (dot == NULL)
					err(1, "Memory allocation error");
				/*
				 * "dir/." will use the same stat(2) as "dir".
				 */
				dot->node = create_fsnode(".",
				    child->node->path, ".", &item->node->inode->st);
				dot->node->type = S_IFDIR;
				dot->node->parent = item->node;
				dot->node->first = dot->node;

				RB_INSERT(rbtree, &rbhead, dot);
				item->node->child = dot->node;
			}
			/*
			 * Place the new item behind the dot to avoid pushing
			 * the dot to the back of the list, also take
			 * the dot's parent.
			 */
			child->node->first = item->node->child->first;
			child->node->next  = item->node->child->next;
			item->node->child->next = child->node;
		}
		if (stop)
			break;

		child = item;
	}
	free(find.node);
	/*
	 * Return the possibly modified root.
	 */
	return (root);
}

static struct mtree_spec *
read_specfile(const char *specfile)
{
	struct mtree_spec *spec;
	FILE *fp;

	spec = mtree_spec_create();
	if (spec == NULL)
		err(1, "Can't create mtree spec");

	mtree_spec_set_read_options(spec, MTREE_READ_MERGE | MTREE_READ_SORT);
	if (strcmp(specfile, "-") == 0)
		fp = stdin;
	else {
		fp = fopen(specfile, "r");
		if (fp == NULL)
			err(1, "Can't open `%s'", specfile);
	}
	if (mtree_spec_read_spec_file(spec, fp) != 0)
		errx(1, "Can't read `%s': %s",
		    specfile, mtree_spec_get_read_error(spec));

	fclose(fp);
	return (spec);
}

fsnode *
read_mtree(const char *specfile, fsnode *node)
{
	struct mtree_spec *spec;
	struct mtree_entry *entry;
	struct rbnode *root;

	setgroupent(1);
	setpassent(1);

	spec = read_specfile(specfile);
	root = malloc(sizeof(struct rbnode));
	if (root == NULL)
		err(1, "Memory allocation error");
	root->node = create_dirnode(".", ".", ".");
	root->node->first = root->node;

	RB_INSERT(rbtree, &rbhead, root);
	entry = mtree_spec_get_entries(spec);
	while (entry != NULL) {
		struct stat st;

		/* Convert entry keywords to stat. */
		memset(&st, 0, sizeof(st));
		entry_to_stat(entry, &st, STAT_KEYWORDS);

		node = create_fsnode(".",
		    mtree_entry_get_dirname(entry),
		    mtree_entry_get_name(entry), &st);
		if (fill_node(node, entry, &st) == 0)
			root->node = rbnode_add(root->node,
			    mtree_entry_get_path(entry),
			    node);
		else
			free_fsnodes(node);

		entry = mtree_entry_get_next(entry);
	}
	if (errors > 0)
		errx(1, "%u error(s) in mtree specfile", errors);

	endpwent();
	endgrent();
	return (root->node);
}

static void
apply_add_nodes(fsnode *node)
{
	struct rbnode *rbn;

	for (; node != NULL; node = node->next) {
		rbn = malloc(sizeof(struct rbnode));
		if (rbn == NULL)
			err(1, "Memory allocation error");
		node->flags |= FSNODE_F_HASSPEC;
		rbn->node = node;
		RB_INSERT(rbtree, &rbhead, rbn);

		if (node->child != NULL)
			apply_add_nodes(node->child);
	}
}

static void
apply_update_node(fsnode *node, struct mtree_entry *entry)
{
	long keywords;

	/*
	 * XXX: ignoring NLINK for now
	 * retained from the pre-libmtree code,
	 * not sure about the reason -- michal
	 */
	keywords = STAT_KEYWORDS & ~(MTREE_KEYWORD_TIME | MTREE_KEYWORD_NLINK);
	entry_to_stat(entry, &node->inode->st, keywords);

	if (node->type != (node->inode->st.st_mode & S_IFMT))
		errx(1, "`%s' type mismatch: specfile %s, tree %s",
		    mtree_entry_get_path(entry),
		    inode_type(node->inode->st.st_mode),
		    inode_type(node->type));

	keywords &= mtree_entry_get_keywords(entry);

	if (keywords & MTREE_KEYWORD_LINK) {
		const char *link;

		link = mtree_entry_get_link(entry);
		free(node->symlink);
		if ((node->symlink = strdup(link)) == NULL)
			err(1, "Memory allocation error");
	}
	if (keywords & MTREE_KEYWORD_TIME) {
		struct mtree_timespec *ts;

		ts = mtree_entry_get_time(entry);
		node->inode->st.st_mtime = ts->tv_sec;
		node->inode->st.st_atime = ts->tv_sec;
		node->inode->st.st_ctime = start_time.tv_sec;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
		node->inode->st.st_mtimensec = ts->tv_nsec;
		node->inode->st.st_atimensec = ts->tv_nsec;
		node->inode->st.st_ctimensec = start_time.tv_nsec;
#endif
	}
}

static fsnode *
apply_add_node(fsnode *root, struct mtree_entry *entry, const char *path,
    const char *name)
{
	struct stat st;
	fsnode *node;
	uint64_t keywords;

	/*
	 * Don't add optional spec entries that are not present in the
	 * file system.
	 */
	keywords = mtree_entry_get_keywords(entry);
	if (keywords & MTREE_KEYWORD_OPTIONAL)
		return (NULL);
	/*
	 * Check required fields.
	 */
	if ((keywords & MTREE_KEYWORD_TYPE) == 0)
		errx(1, "`%s/%s': type not provided", path, name);
	if ((keywords & MTREE_KEYWORD_MODE) == 0)
		errx(1, "`%s/%s': mode not provided", path, name);
	if ((keywords & MTREE_KEYWORD_MASK_GROUP) == 0)
		errx(1, "`%s/%s': group not provided", path, name);
	if ((keywords & MTREE_KEYWORD_MASK_USER) == 0)
		errx(1, "`%s/%s': user not provided", path, name);

	memset(&st, 0, sizeof(st));
	entry_to_stat(entry, &st, MTREE_KEYWORD_TYPE);
	st.st_nlink = 1;
	st.st_mtime =
	    st.st_atime =
	    st.st_ctime = start_time.tv_sec;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
	st.st_mtimensec =
	    st.st_atimensec =
	    st.st_ctimensec = start_time.tv_nsec;
#endif
	node = create_fsnode(".", path, name, &st);

	apply_update_node(node, entry);
	if (S_ISDIR(st.st_mode)) {
		node->child = create_fsnode(".",
		    mtree_entry_get_path(entry), ".", &st);
		node->child->parent = node;
		node->child->first = node->child;
		apply_update_node(node, entry);
	}
	return (node);
}

void
apply_specfile(const char *specfile, const char *subtree, fsnode *root, int only)
{
	struct mtree_spec *spec;
	struct mtree_entry *entry;
	struct rbnode find;
	const char *path;
	char buf[MAXPATHLEN + 1];
	size_t len;
	char *end;
	struct rbnode *rbn;
	fsnode *node;

	(void)subtree;
	(void)only;

	spec = read_specfile(specfile);
	apply_add_nodes(root);
	find.node = malloc(sizeof(struct rbnode));
	if (find.node == NULL)
		err(1, "Memory allocation error");

	entry = mtree_spec_get_entries(spec);
	while (entry != NULL) {
		find.node->name = (char *)mtree_entry_get_name(entry);

		path = mtree_entry_get_path(entry);
		if (IS_DOT(path))
			find.node->path = (char *)path;
		else {
			len = strlen(path);
			if (len > MAXPATHLEN)
				errx(1, "Pathname too long.");
			end = stpcpy(buf, path) - 1;
			/*
			 * libmtree guarantees that every relative path is
			 * prefixed with "./"
			 */
			while (*end != '/')
				end--;
			while (*end == '/')
				end--;
			*(end + 1) = '\0';
			find.node->path = buf;
		}

		rbn = RB_FIND(rbtree, &rbhead, &find);
		if (rbn == NULL) {
			node = apply_add_node(root, entry,
			    find.node->path,
			    find.node->name);
			if (node != NULL) {
				/*
				 * Connect the created node to the parent node.
				 *
				 * If parent node doesn't exist, create chain
				 * of nodes up to the first existing node.
				 */
				root = rbnode_add(root,
				    mtree_entry_get_path(entry), node);
			}
		} else {
			apply_update_node(rbn->node, entry);
			RB_REMOVE(rbtree, &rbhead, rbn);
		}

		entry = mtree_entry_get_next(entry);
	}
}
