/*
 *  Device operations for the pnfs nfs4 placement layout driver.
 *
 *  Copyright (c) 2002
 *  The Regents of the University of Michigan
 *  All Rights Reserved
 *
 *  Dean Hildebrand <dhildebz@umich.edu>
 *  Garth Goodson   <Garth.Goodson@netapp.com>
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

#include <linux/nfs_fs.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/sunrpc/addr.h>

#include "../internal.h"
#include "../nfs4session.h"
#include "placelayout.h"

#define NFSDBG_FACILITY		NFSDBG_PNFS_LD

static unsigned int dataserver_timeo = NFS4_DEF_DS_TIMEO;
static unsigned int dataserver_retrans = NFS4_DEF_DS_RETRANS;

/*
 * Data server cache
 *
 * Data servers can be mapped to different device ids.
 * pnfs_pl_ds reference counting
 *   - set to 1 on allocation
 *   - incremented when a device id maps a data server already in the cache.
 *   - decremented when deviceid is removed from the cache.
 */
static DEFINE_SPINLOCK(nfs4_ds_cache_lock);
static LIST_HEAD(pnfs_pl_data_server_cache);

/* Debug routines */
void
print_ds(struct pnfs_pl_ds *ds)
{
	if (ds == NULL) {
		printk("%s NULL device\n", __func__);
		return;
	}
	printk("        ds %s\n"
		"        ref count %d\n"
		"        client %p\n"
		"        cl_exchange_flags %x\n",
		ds->ds_remotestr,
		atomic_read(&ds->ds_count), ds->ds_clp,
		ds->ds_clp ? ds->ds_clp->cl_exchange_flags : 0);
}

static bool
same_sockaddr(struct sockaddr *addr1, struct sockaddr *addr2)
{
	struct sockaddr_in *a, *b;
	struct sockaddr_in6 *a6, *b6;

	if (addr1->sa_family != addr2->sa_family)
		return false;

	switch (addr1->sa_family) {
	case AF_INET:
		a = (struct sockaddr_in *)addr1;
		b = (struct sockaddr_in *)addr2;

		if (a->sin_addr.s_addr == b->sin_addr.s_addr &&
		    a->sin_port == b->sin_port)
			return true;
		break;

	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr1;
		b6 = (struct sockaddr_in6 *)addr2;

		/* LINKLOCAL addresses must have matching scope_id */
		if (ipv6_addr_src_scope(&a6->sin6_addr) ==
		    IPV6_ADDR_SCOPE_LINKLOCAL &&
		    a6->sin6_scope_id != b6->sin6_scope_id)
			return false;

		if (ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		    a6->sin6_port == b6->sin6_port)
			return true;
		break;

	default:
		dprintk("%s: unhandled address family: %u\n",
			__func__, addr1->sa_family);
		return false;
	}

	return false;
}

/*
 * Lookup DS by addresses.  nfs4_ds_cache_lock is held
 */
static struct pnfs_pl_ds *
_data_server_lookup_locked(const struct pnfs_pl_ds_addr *da)
{
	struct pnfs_pl_ds *ds;

	list_for_each_entry(ds, &pnfs_pl_data_server_cache, ds_node)
		if (same_sockaddr((struct sockaddr *)&ds->ds_addr->da_addr,
				   (struct sockaddr *)&da->da_addr))
			return ds;
	return NULL;
}

/*
 * Create an rpc connection to the pnfs_pl_ds data server
 * Currently only supports IPv4 and IPv6 addresses
 */
static int
pnfs_pl_ds_connect(struct nfs_server *mds_srv, struct pnfs_pl_ds *ds)
{
	struct nfs_client *clp = ERR_PTR(-EIO);
	struct pnfs_pl_ds_addr *da;
	int status = 0;

	dprintk("--> %s DS %s au_flavor %d\n", __func__, ds->ds_remotestr,
		mds_srv->nfs_client->cl_rpcclient->cl_auth->au_flavor);

	da = ds->ds_addr;
	dprintk("%s: DS %s: trying address %s\n",
		__func__, ds->ds_remotestr, da->da_remotestr);

	clp = nfs4_set_ds_client(mds_srv->nfs_client,
			(struct sockaddr *)&da->da_addr,
			da->da_addrlen, IPPROTO_TCP,
			dataserver_timeo, dataserver_retrans);
	if (IS_ERR(clp)) {
		status = PTR_ERR(clp);
		goto out;
	}

	status = nfs4_init_ds_session(clp, mds_srv->nfs_client->cl_lease_time);
	if (status)
		goto out_put;

	smp_wmb();
	ds->ds_clp = clp;
	dprintk("%s [new] addr: %s\n", __func__, ds->ds_remotestr);
out:
	return status;
out_put:
	nfs_put_client(clp);
	goto out;
}

static void
pl_destroy_ds(struct pnfs_pl_ds *ds)
{
	dprintk("--> %s\n", __func__);
	ifdebug(FACILITY)
		print_ds(ds);

	if (ds->ds_clp)
		nfs_put_client(ds->ds_clp);

	kfree(ds->ds_addr->da_remotestr);
	kfree(ds->ds_addr);

	kfree(ds->ds_remotestr);
	kfree(ds);
}

void
nfs4_pl_free_deviceid(struct nfs4_place_layout_dsaddr *dsaddr)
{
	struct pnfs_pl_ds *ds;
	int i;

	nfs4_print_deviceid(&dsaddr->id_node.deviceid);

	for (i = 0; i < dsaddr->num_ds; i++) {
		ds = dsaddr->ds_list[i];
		if (ds != NULL) {
			if (atomic_dec_and_lock(&ds->ds_count,
						&nfs4_ds_cache_lock)) {
				list_del_init(&ds->ds_node);
				spin_unlock(&nfs4_ds_cache_lock);
				pl_destroy_ds(ds);
			}
		}
	}
	kfree(dsaddr->stripe_indices);
	kfree(dsaddr);
}

static struct pnfs_pl_ds *
pnfs_pl_ds_add(struct pnfs_pl_ds_addr *da, gfp_t gfp_flags)
{
	struct pnfs_pl_ds *tmp_ds, *ds = NULL;

	if (!da) {
		dprintk("%s: no address defined\n", __func__);
		goto out;
	}

	ds = kzalloc(sizeof(*ds), gfp_flags);
	if (!ds)
		goto out;

	spin_lock(&nfs4_ds_cache_lock);
	tmp_ds = _data_server_lookup_locked(da);
	if (tmp_ds == NULL) {
		ds->ds_addr = da;
		/* this is only used for debugging, so it's ok if its NULL */
		ds->ds_remotestr = kstrdup(da->da_remotestr, gfp_flags);
		atomic_set(&ds->ds_count, 1);
		INIT_LIST_HEAD(&ds->ds_node);
		ds->ds_clp = NULL;
		list_add(&ds->ds_node, &pnfs_pl_data_server_cache);
		dprintk("%s add new data server %s\n", __func__,
			ds->ds_remotestr);
	} else {
		kfree(ds);
		atomic_inc(&tmp_ds->ds_count);
		dprintk("%s data server %s found, inc'ed ds_count to %d\n",
			__func__, tmp_ds->ds_remotestr,
			atomic_read(&tmp_ds->ds_count));
		ds = tmp_ds;
	}
	spin_unlock(&nfs4_ds_cache_lock);
out:
	return ds;
}

/*
 * Currently only supports ipv4, ipv6 and one multi-path address.
 */
static struct pnfs_pl_ds_addr *
pl_decode_ds_addr(struct net *net, struct xdr_stream *streamp, gfp_t gfp_flags)
{
	struct pnfs_pl_ds_addr *da = NULL;
	char *buf, *portstr;
	__be16 port;
	int nlen, rlen;
	int tmp[2];
	__be32 *p;
	char *netid, *match_netid;
	size_t len, match_netid_len;
	char *startsep = "";
	char *endsep = "";


	/* r_netid */
	p = xdr_inline_decode(streamp, 4);
	dprintk("%s: 1 %p\n", __func__, p);
	if (unlikely(!p))
		goto out_err;
	nlen = be32_to_cpup(p++);
	dprintk("%s: 1 %d\n", __func__, nlen);

	p = xdr_inline_decode(streamp, nlen);
	dprintk("%s: 2 %p\n", __func__, p);
	if (unlikely(!p))
		goto out_err;

	netid = kmalloc(nlen+1, gfp_flags);
	dprintk("%s: 3 %p\n", __func__, netid);
	if (unlikely(!netid))
		goto out_err;

	netid[nlen] = '\0';
	memcpy(netid, p, nlen);
	dprintk("%s: 3 %s\n", __func__, netid);

	/* r_addr: ip/ip6addr with port in dec octets - see RFC 5665 */
	p = xdr_inline_decode(streamp, 4);
	dprintk("%s: 4 %p\n", __func__, p);
	if (unlikely(!p))
		goto out_free_netid;
	rlen = be32_to_cpup(p);
	dprintk("%s: 4 rlen: %d\n", __func__, rlen);

	p = xdr_inline_decode(streamp, rlen);
	dprintk("%s: 5 %p\n", __func__, p);
	if (unlikely(!p))
		goto out_free_netid;

	/* port is ".ABC.DEF", 8 chars max */
	if (rlen > INET6_ADDRSTRLEN + IPV6_SCOPE_ID_LEN + 8) {
		dprintk("%s: Invalid address, length %d\n", __func__,
			rlen);
		goto out_free_netid;
	}
	buf = kmalloc(rlen + 1, gfp_flags);
	if (!buf) {
		dprintk("%s: Not enough memory\n", __func__);
		goto out_free_netid;
	}
	buf[rlen] = '\0';
	memcpy(buf, p, rlen);

	/* replace port '.' with '-' */
	portstr = strrchr(buf, '.');
	if (!portstr) {
		dprintk("%s: Failed finding expected dot in port\n",
			__func__);
		goto out_free_buf;
	}
	*portstr = '-';

	/* find '.' between address and port */
	portstr = strrchr(buf, '.');
	if (!portstr) {
		dprintk("%s: Failed finding expected dot between address and "
			"port\n", __func__);
		goto out_free_buf;
	}
	*portstr = '\0';

	da = kzalloc(sizeof(*da), gfp_flags);
	dprintk("%s: 6 %p\n", __func__, da);
	if (unlikely(!da))
		goto out_free_buf;

	if (!rpc_pton(net, buf, portstr-buf, (struct sockaddr *)&da->da_addr,
		      sizeof(da->da_addr))) {
		dprintk("%s: error parsing address %s\n", __func__, buf);
		goto out_free_da;
	}

	portstr++;
	sscanf(portstr, "%d-%d", &tmp[0], &tmp[1]);
	port = htons((tmp[0] << 8) | (tmp[1]));

	switch (da->da_addr.ss_family) {
	case AF_INET:
		((struct sockaddr_in *)&da->da_addr)->sin_port = port;
		da->da_addrlen = sizeof(struct sockaddr_in);
		match_netid = "tcp";
		match_netid_len = 3;
		break;

	case AF_INET6:
		((struct sockaddr_in6 *)&da->da_addr)->sin6_port = port;
		da->da_addrlen = sizeof(struct sockaddr_in6);
		match_netid = "tcp6";
		match_netid_len = 4;
		startsep = "[";
		endsep = "]";
		break;

	default:
		dprintk("%s: unsupported address family: %u\n",
			__func__, da->da_addr.ss_family);
		goto out_free_da;
	}

	if (nlen != match_netid_len || strncmp(netid, match_netid, nlen)) {
		dprintk("%s: ERROR: r_netid \"%s\" != \"%s\"\n",
			__func__, netid, match_netid);
		goto out_free_da;
	}

	/* save human readable address */
	len = strlen(startsep) + strlen(buf) + strlen(endsep) + 7;
	da->da_remotestr = kzalloc(len, gfp_flags);

	/* NULL is ok, only used for dprintk */
	if (da->da_remotestr)
		snprintf(da->da_remotestr, len, "%s%s%s:%u", startsep,
			 buf, endsep, ntohs(port));

	dprintk("%s: Parsed DS addr %s\n", __func__, da->da_remotestr);
	kfree(buf);
	kfree(netid);
	return da;

out_free_da:
	kfree(da);
out_free_buf:
	dprintk("%s: Error parsing DS addr: %s\n", __func__, buf);
	kfree(buf);
out_free_netid:
	kfree(netid);
out_err:
	return NULL;
}

/* Decode opaque device data and return the result */
struct nfs4_place_layout_dsaddr *
nfs4_pl_alloc_deviceid_node(struct nfs_server *server, struct pnfs_device *pdev,
		gfp_t gfp_flags)
{
	int i;
	u32 cnt, num;
	u8 *indexp;
	__be32 *p;
	u8 *stripe_indices;
	u8 max_stripe_index;
	struct nfs4_place_layout_dsaddr *dsaddr = NULL;
	struct xdr_stream stream;
	struct xdr_buf buf;
	struct page *scratch;
	struct pnfs_pl_ds_addr *da;

	/* set up xdr stream */
	scratch = alloc_page(gfp_flags);
	if (!scratch)
		goto out_err;

	xdr_init_decode_pages(&stream, &buf, pdev->pages, pdev->pglen);
	xdr_set_scratch_buffer(&stream, page_address(scratch), PAGE_SIZE);

	/* Get the stripe count (number of stripe index) */
	p = xdr_inline_decode(&stream, 4);
	if (unlikely(!p))
		goto out_err_free_scratch;

	cnt = be32_to_cpup(p);
	dprintk("%s stripe count  %d\n", __func__, cnt);
	if (cnt > NFS4_PNFS_MAX_STRIPE_CNT) {
		printk(KERN_WARNING "NFS: %s: stripe count %d greater than "
		       "supported maximum %d\n", __func__,
			cnt, NFS4_PNFS_MAX_STRIPE_CNT);
		goto out_err_free_scratch;
	}

	/* read stripe indices */
	stripe_indices = kcalloc(cnt, sizeof(u8), gfp_flags);
	if (!stripe_indices)
		goto out_err_free_scratch;

	p = xdr_inline_decode(&stream, cnt << 2);
	if (unlikely(!p))
		goto out_err_free_stripe_indices;

	indexp = &stripe_indices[0];
	max_stripe_index = 0;
	for (i = 0; i < cnt; i++) {
		*indexp = be32_to_cpup(p++);
		max_stripe_index = max(max_stripe_index, *indexp);
		indexp++;
	}

	/* Check the multipath list count */
	p = xdr_inline_decode(&stream, 4);
	if (unlikely(!p))
		goto out_err_free_stripe_indices;

	num = be32_to_cpup(p);
	dprintk("%s num_ds %u\n", __func__, num);
	if (num > NFS4_PNFS_MAX_MULTI_CNT) {
		printk(KERN_WARNING "NFS: %s: multipath count %d greater than "
			"supported maximum %d\n", __func__,
			num, NFS4_PNFS_MAX_MULTI_CNT);
		goto out_err_free_stripe_indices;
	}

	/* validate stripe indices are all < num */
	if (max_stripe_index >= num) {
		printk(KERN_WARNING "NFS: %s: stripe index %u >= num ds %u\n",
			__func__, max_stripe_index, num);
		goto out_err_free_stripe_indices;
	}

	dsaddr = kzalloc(sizeof(*dsaddr) +
			(sizeof(struct pnfs_pl_ds *) * (num - 1)),
			gfp_flags);
	if (!dsaddr)
		goto out_err_free_stripe_indices;

	dsaddr->stripe_count = cnt;
	dsaddr->stripe_indices = stripe_indices;
	stripe_indices = NULL;
	dsaddr->num_ds = num;
	nfs4_init_deviceid_node(&dsaddr->id_node, server, &pdev->dev_id);

	for (i = 0; i < dsaddr->num_ds; i++) {
		/* multipath count (always one; skip */
		p = xdr_inline_decode(&stream, 4);
		if (unlikely(!p))
			goto out_err_free_deviceid;

		da = pl_decode_ds_addr(server->nfs_client->cl_net, &stream, gfp_flags);
		if (!da) {
			dprintk("%s: no suitable DS address found\n", __func__);
			goto out_err_free_deviceid;
		}

		dsaddr->ds_list[i] = pnfs_pl_ds_add(da, gfp_flags);
		if (!dsaddr->ds_list[i])
			goto out_err_free_da;

		/* If DS was already in cache, free ds addrs */
		if (da != dsaddr->ds_list[i]->ds_addr) {
			kfree(da->da_remotestr);
			kfree(da);
		}
	}

	__free_page(scratch);
	return dsaddr;

out_err_free_da:
	kfree(da->da_remotestr);
	kfree(da);
out_err_free_deviceid:
	nfs4_pl_free_deviceid(dsaddr);
	/* stripe_indicies was part of dsaddr */
	goto out_err_free_scratch;
out_err_free_stripe_indices:
	kfree(stripe_indices);
out_err_free_scratch:
	__free_page(scratch);
out_err:
	dprintk("%s ERROR: returning NULL\n", __func__);
	return NULL;
}

void
nfs4_pl_put_deviceid(struct nfs4_place_layout_dsaddr *dsaddr)
{
	nfs4_put_deviceid_node(&dsaddr->id_node);
}

/*
 * Want res = (offset)/ layout->stripe_unit
 * Then: ((res + fsi) % dsaddr->stripe_count)
 */
u32
nfs4_pl_calc_j_index(struct pnfs_layout_segment *lseg, loff_t offset)
{
	struct nfs4_placelayout_segment *flseg = PLACELAYOUT_LSEG(lseg);
	u64 tmp;

	tmp = offset;
	do_div(tmp, flseg->stripe_unit);
	return do_div(tmp, flseg->dsaddr->stripe_count);
}

u32
nfs4_pl_calc_ds_index(struct pnfs_layout_segment *lseg, u32 j)
{
	return PLACELAYOUT_LSEG(lseg)->dsaddr->stripe_indices[j];
}

struct nfs_fh *
nfs4_pl_select_ds_fh(struct pnfs_layout_segment *lseg, u32 j)
{
	struct nfs4_placelayout_segment *flseg = PLACELAYOUT_LSEG(lseg);
	u32 i;

	if (flseg->stripe_type == STRIPE_SPARSE) {
		if (flseg->num_fh == 1)
			i = 0;
		else if (flseg->num_fh == 0)
			/* Use the MDS OPEN fh set in nfs_read_rpcsetup */
			return NULL;
		else
			i = nfs4_pl_calc_ds_index(lseg, j);
	} else
		i = j;
	return flseg->fh_array[i];
}

static void pnfs_pl_wait_ds_connect(struct pnfs_pl_ds *ds)
{
	might_sleep();
	wait_on_bit_action(&ds->ds_state, NFS4DS_CONNECTING,
			   nfs_wait_bit_killable, TASK_KILLABLE);
}

static void pnfs_pl_clear_ds_conn_bit(struct pnfs_pl_ds *ds)
{
	smp_mb__before_atomic();
	clear_bit(NFS4DS_CONNECTING, &ds->ds_state);
	smp_mb__after_atomic();
	wake_up_bit(&ds->ds_state, NFS4DS_CONNECTING);
}


struct pnfs_pl_ds *
nfs4_pl_prepare_ds(struct pnfs_layout_segment *lseg, u32 ds_idx)
{
	struct nfs4_place_layout_dsaddr *dsaddr = PLACELAYOUT_LSEG(lseg)->dsaddr;
	struct pnfs_pl_ds *ds = dsaddr->ds_list[ds_idx];
	struct nfs4_deviceid_node *devid = PLACELAYOUT_DEVID_NODE(lseg);
	struct pnfs_pl_ds *ret = ds;

	if (ds == NULL) {
		printk(KERN_ERR "NFS: %s: No data server for offset index %d\n",
			__func__, ds_idx);
		placelayout_mark_devid_invalid(devid);
		goto out;
	}
	smp_rmb();
	if (ds->ds_clp)
		goto out_test_devid;

	if (test_and_set_bit(NFS4DS_CONNECTING, &ds->ds_state) == 0) {
		struct nfs_server *s = NFS_SERVER(lseg->pls_layout->plh_inode);
		int err;

		err = pnfs_pl_ds_connect(s, ds);
		if (err)
			nfs4_mark_deviceid_unavailable(devid);
		pnfs_pl_clear_ds_conn_bit(ds);
	} else {
		/* Either ds is connected, or ds is NULL */
		pnfs_pl_wait_ds_connect(ds);
	}
out_test_devid:
	if (placelayout_test_devid_unavailable(devid))
		ret = NULL;
out:
	return ret;
}

module_param(dataserver_retrans, uint, 0644);
MODULE_PARM_DESC(dataserver_retrans, "The  number of times the NFSv4.1 client "
			"retries a request before it attempts further "
			" recovery  action.");
module_param(dataserver_timeo, uint, 0644);
MODULE_PARM_DESC(dataserver_timeo, "The time (in tenths of a second) the "
			"NFSv4.1  client  waits for a response from a "
			" data server before it retries an NFS request.");
