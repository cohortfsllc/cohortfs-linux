/*
 *  NFSv4 placement layout driver data structures.
 *
 *  Copyright (c) 2002
 *  The Regents of the University of Michigan
 *  All Rights Reserved
 *
 *  Dean Hildebrand <dhildebz@umich.edu>
 *
 *  Permission is granted to use, copy, create derivative works, and
 *  redistribute this software and such derivative works for any purpose,
 *  so long as the name of the University of Michigan is not used in
 *  any advertising or publicity pertaining to the use or distribution
 *  of this software without specific, written prior authorization. If
 *  the above copyright notice or any other identification of the
 *  University of Michigan is included in any copy of any portion of
 *  this software, then the disclaimer below must also be included.
 *
 *  This software is provided as is, without representation or warranty
 *  of any kind either express or implied, including without limitation
 *  the implied warranties of merchantability, fitness for a particular
 *  purpose, or noninfringement.  The Regents of the University of
 *  Michigan shall not be liable for any damages, including special,
 *  indirect, incidental, or consequential damages, with respect to any
 *  claim arising out of or in connection with the use of the software,
 *  even if it has been or is hereafter advised of the possibility of
 *  such damages.
 */

#ifndef FS_NFS_NFS4PLACELAYOUT_H
#define FS_NFS_NFS4PLACELAYOUT_H

#include "../pnfs.h"

/*
 * Default data server connection timeout and retrans vaules.
 * Set by module paramters dataserver_timeo and dataserver_retrans.
 */
#define NFS4_DEF_DS_TIMEO   600 /* in tenths of a second */
#define NFS4_DEF_DS_RETRANS 5

/*
 * Field testing shows we need to support up to 4096 stripe indices.
 * We store each index as a u8 (u32 on the wire) to keep the memory footprint
 * reasonable. This in turn means we support a maximum of 256
 * RFC 5661 multipath_list4 structures.
 */
#define NFS4_PNFS_MAX_STRIPE_CNT 4096
#define NFS4_PNFS_MAX_MULTI_CNT  256 /* 256 fit into a u8 stripe_index */

/* error codes for internal use */
#define NFS4ERR_RESET_TO_MDS   12001

enum stripetype4 {
	STRIPE_SPARSE = 1,
	STRIPE_DENSE = 2
};

/* Individual ip address */
struct pnfs_pl_ds_addr {
	struct sockaddr_storage	da_addr;
	size_t			da_addrlen;
	char			*da_remotestr;	/* human readable addr+port */
};

struct pnfs_pl_ds {
	struct list_head		ds_node;  /* nfs4_pnfs_dev_hlist dev_dslist */
	char					*ds_remotestr;	/* human readable address */
	struct pnfs_pl_ds_addr	*ds_addr;
	struct nfs_client		*ds_clp;
	atomic_t				ds_count;
	unsigned long			ds_state;
#define NFS4DS_CONNECTING	0	/* ds is establishing connection */
};

struct nfs4_place_layout_dsaddr {
	struct nfs4_deviceid_node	id_node;
	u32				stripe_count;
	u8				*stripe_indices;
	u32				num_ds;
	struct pnfs_pl_ds		*ds_list[1];
};

struct nfs4_placelayout_segment {
	struct pnfs_layout_segment generic_hdr;
	u32 stripe_type;
	u32 commit_through_mds;
	u32 stripe_unit;
	struct nfs4_place_layout_dsaddr *dsaddr; /* Point to GETDEVINFO data */
	unsigned int num_fh;
	struct nfs_fh **fh_array;
};

struct nfs4_placelayout {
	struct pnfs_layout_hdr generic_hdr;
	struct pnfs_ds_commit_info commit_info;
};

static inline struct nfs4_placelayout *
PLACELAYOUT_FROM_HDR(struct pnfs_layout_hdr *lo)
{
	return container_of(lo, struct nfs4_placelayout, generic_hdr);
}

static inline struct nfs4_placelayout_segment *
PLACELAYOUT_LSEG(struct pnfs_layout_segment *lseg)
{
	return container_of(lseg,
			    struct nfs4_placelayout_segment,
			    generic_hdr);
}

static inline struct nfs4_deviceid_node *
PLACELAYOUT_DEVID_NODE(struct pnfs_layout_segment *lseg)
{
	return &PLACELAYOUT_LSEG(lseg)->dsaddr->id_node;
}

static inline void
placelayout_mark_devid_invalid(struct nfs4_deviceid_node *node)
{
	u32 *p = (u32 *)&node->deviceid;

	printk(KERN_WARNING "NFS: Deviceid [%x%x%x%x] marked out of use.\n",
		p[0], p[1], p[2], p[3]);

	set_bit(NFS_DEVICEID_INVALID, &node->flags);
}

static inline bool
placelayout_test_devid_invalid(struct nfs4_deviceid_node *node)
{
	return test_bit(NFS_DEVICEID_INVALID, &node->flags);
}

extern bool
placelayout_test_devid_unavailable(struct nfs4_deviceid_node *node);

extern struct nfs_fh *
nfs4_pl_select_ds_fh(struct pnfs_layout_segment *lseg, u32 j);

extern void print_ds(struct pnfs_pl_ds *ds);
u32 nfs4_pl_calc_j_index(struct pnfs_layout_segment *lseg, loff_t offset);
u32 nfs4_pl_calc_ds_index(struct pnfs_layout_segment *lseg, u32 j);
struct pnfs_pl_ds *nfs4_pl_prepare_ds(struct pnfs_layout_segment *lseg,
					u32 ds_idx);

extern struct nfs4_place_layout_dsaddr *
nfs4_pl_alloc_deviceid_node(struct nfs_server *server,
	struct pnfs_device *pdev, gfp_t gfp_flags);
extern void nfs4_pl_put_deviceid(struct nfs4_place_layout_dsaddr *dsaddr);
extern void nfs4_pl_free_deviceid(struct nfs4_place_layout_dsaddr *dsaddr);

#endif /* FS_NFS_NFS4PLACELAYOUT_H */
