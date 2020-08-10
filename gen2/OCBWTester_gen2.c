#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/uuid.h>
#include <linux/cpumask.h>
#include <linux/lightnvm.h>
#include <linux/bitmap.h>
#include <linux/proc_fs.h>

#define OCBWT_SUBMIT_QD (8)
#define OCBWT_BIO_NRVEC (8)
#define OCBWT_BIOPAGE_ALLOC_ORDER (3)
#define OCBWT_BIOPAGE_NUM (1 << OCBWT_BIOPAGE_ALLOC_ORDER)

enum {
	OCBWT_UNINITIALIZED = 0,
	OCBWT_INITIALIZED,
};

#define ocmbt_dma_meta_size (sizeof(unsigned long) * 128)


struct ocbwt_global_status {
	unsigned long nr_chnls;
};

struct ocbwt_pch_status {
	unsigned long inflight;
	unsigned long finished;
	unsigned long r_finished;
};

struct ocbwt_r_ctx {
	struct nvm_rq rqd;
	struct bio *bio;
	struct page *pages;
	struct bvec_iter saved_iter;
	volatile int status;
};

struct per_readerwriter_info {
	/* Writer task struct */
	struct task_struct *writer_ts;
	struct task_struct *reader_ts;

	/* Parameters for writers. */
	struct ocbw_tester *ocbwt;
	unsigned int writer_index;
	volatile int writer_running_state;
	volatile int reader_running_state;

	/* Variables that used by the writer. */
	atomic64_t finish_counter;
	atomic_t inflight_requests;
	atomic64_t r_finish_counter;

	/* Pre-allocated read requests */
	struct ocbwt_r_ctx *rctx;

	int wc_lun;
	int wc_pln;
	int wc_blk;
	int wc_pg;
	int wc_sec;

	int rc_lun;
	int rc_pln;
	int rc_blk;
	int rc_pg;
	int rc_sec;
};

struct ocbw_tester {
	struct nvm_tgt_dev *dev;
	struct gendisk *fake_disk;
	unsigned int oc_channels;
	int nr_luns;
	int nr_planes;
	int nr_blks;
	int pgs_per_blk;
	int sec_per_page;
	int plane_mode;
	struct per_readerwriter_info *pwi;
	unsigned int status_size;
};

struct ocbw_tester *global_tester;

static struct ppa_addr ocbwt_calculate_ppa(struct ocbw_tester *tester,
									struct per_readerwriter_info *wi, int isWrite)
{
	struct ppa_addr ppa = {.ppa=0};

	if (isWrite) {
		ppa.g.blk = wi->wc_blk;
		ppa.g.pg = wi->wc_pg;
		ppa.g.sec = wi->wc_sec;
		ppa.g.pl = wi->wc_pln;
		ppa.g.lun = wi->wc_lun;
		ppa.g.ch = wi->writer_index;

		wi->wc_sec++;
		if (wi->wc_sec == tester->sec_per_page) {
			wi->wc_sec = 0;
			wi->wc_pln++;
			if (wi->wc_pln == tester->nr_planes) {
				wi->wc_pln = 0;
				wi->wc_lun++;
				if (wi->wc_lun == tester->nr_luns) {
					wi->wc_lun = 0;
					wi->wc_pg++;
					if (wi->wc_pg == tester->pgs_per_blk) {
						wi->wc_pg = 0;
						wi->wc_blk++;
						if (wi->wc_blk == tester->nr_blks)
							wi->wc_blk = 0;
					}
				}
			}
		}
	}else {
		ppa.g.blk = wi->rc_blk;
		ppa.g.pg = wi->rc_pg;
		ppa.g.sec = wi->rc_sec;
		ppa.g.pl = wi->rc_pln;
		ppa.g.lun = wi->rc_lun;
		ppa.g.ch = wi->writer_index;

		wi->rc_sec++;
		if (wi->rc_sec == tester->sec_per_page) {
			wi->rc_sec = 0;
			wi->rc_pln++;
			if (wi->rc_pln == tester->nr_planes) {
				wi->rc_pln = 0;
				wi->rc_lun++;
				if (wi->rc_lun == tester->nr_luns) {
					wi->rc_lun = 0;
					wi->rc_pg++;
					if (wi->rc_pg == tester->pgs_per_blk) {
						wi->rc_pg = 0;
						wi->rc_blk++;
						if (wi->rc_blk == tester->nr_blks)
							wi->rc_blk = 0;
					}
				}
			}
		}
	}
	
	return ppa;
}

static void ocbwt_end_io_write(struct nvm_rq *rqd)
{
	struct per_readerwriter_info *wi = rqd->private;
	struct bio *bio = rqd->bio;

	if (rqd->error) {
		pr_err("Write error %d\n", rqd->error);
	}

	//pr_notice("Finish rqd wi %u\n", wi->writer_index);
	atomic64_inc(&wi->finish_counter);
	atomic_dec(&wi->inflight_requests);

	nvm_dev_dma_free(wi->ocbwt->dev->parent, rqd->meta_list, rqd->dma_meta_list);
	kfree(rqd);
	__free_pages(bio_first_page_all(bio), OCBWT_BIOPAGE_ALLOC_ORDER);
	bio_put(bio);
}

static void ocbwt_end_io_read(struct nvm_rq *rqd)
{
	struct per_readerwriter_info *rwi = rqd->private;
	struct ocbwt_r_ctx *rctx = container_of(rqd, struct ocbwt_r_ctx, rqd);

	if (rqd->error) {
		if (rqd->error != NVM_RSP_ERR_EMPTYPAGE)
			pr_err("Read error %d\n", rqd->error);
	}

	WRITE_ONCE(rctx->status, 0);
	//pr_notice("Finish rqd wi %u\n", wi->writer_index);
	atomic64_inc(&rwi->r_finish_counter);
}


static void noinline ocbwt_issue_read_nowait(struct per_readerwriter_info *rwi, int req_idx)
{
	struct ocbwt_r_ctx *rctx = &rwi->rctx[req_idx];
	struct nvm_rq *rqd = &rctx->rqd;
	struct bio *bio = rctx->bio;
	int i, ret;
	struct ocbw_tester *tester = rwi->ocbwt;

	WRITE_ONCE(rctx->status, 1);
	bio->bi_iter = rctx->saved_iter;
	for (i = 0; i < OCBWT_BIOPAGE_NUM; i++)
		rqd->ppa_list[i] = ocbwt_calculate_ppa(tester, rwi, 0);

	ret = nvm_submit_io_nowait(tester->dev, rqd);
	if (ret)
		rctx->status = 0;
}

static void noinline ocbwt_issue_read_requests(struct per_readerwriter_info *rwi)
{
	int i;

	for (i = 0; i < OCBWT_SUBMIT_QD; i++) {
		struct ocbwt_r_ctx *rctx = &rwi->rctx[i];

		if (rctx->status)
			continue;
		ocbwt_issue_read_nowait(rwi, i);
	}
}


static int ocbwt_issue_write_nowait(struct per_readerwriter_info *wi)
{
	struct nvm_rq *rqd;
	struct bio *bio;
	int ret;
	struct page *pages;
	int i;
	unsigned long pfn;
	struct page *page;
	struct ocbw_tester *tester = wi->ocbwt;

	bio = bio_alloc(GFP_ATOMIC, OCBWT_BIO_NRVEC);
	if (!bio)
		return -ENOMEM;

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	pages = alloc_pages(GFP_ATOMIC, OCBWT_BIOPAGE_ALLOC_ORDER);
	if (!pages) {
		ret = -ENOMEM;
		goto outPutBIO;
	}
		
	pfn = page_to_pfn(pages);
	for (i = 0; i < OCBWT_BIOPAGE_NUM; i++) {
		page = pfn_to_page(pfn);
		bio_add_page(bio, page, PAGE_SIZE, 0);
		pfn++;
	}

	rqd = kmalloc(sizeof(*rqd), GFP_ATOMIC);
	if (unlikely(!rqd)) {
		ret = -ENOMEM;
		goto outFreePages;
	}

	rqd->bio = bio;
	rqd->dev = tester->dev;
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = OCBWT_BIOPAGE_NUM;
	rqd->flags = (tester->plane_mode >> 1) | NVM_IO_SCRAMBLE_ENABLE;

	rqd->private = wi;
	rqd->end_io = ocbwt_end_io_write;

	rqd->meta_list = nvm_dev_dma_alloc(tester->dev->parent, GFP_ATOMIC,
							&rqd->dma_meta_list);
	if (!rqd->meta_list) {
		ret = -ENOMEM;
		goto outFreeRQD;
	}

	rqd->ppa_list = rqd->meta_list + ocmbt_dma_meta_size;
	rqd->dma_ppa_list = rqd->dma_meta_list + ocmbt_dma_meta_size;
	rqd->ppa_status = rqd->error = 0;

	for (i = 0; i < OCBWT_BIOPAGE_NUM; i++)
		rqd->ppa_list[i] = ocbwt_calculate_ppa(tester, wi, 1);

	//pr_notice("%s, ch[%u] ppa=0x%llx\n",
	//		__func__, wi->writer_index, rqd->ppa_list[0].ppa);

	ret = nvm_submit_io_nowait(tester->dev, rqd);
	if (ret)
		goto submit_err_out;
	return ret;

submit_err_out:
	nvm_dev_dma_free(tester->dev->parent, rqd->meta_list, rqd->dma_meta_list);
outFreeRQD:
	kfree(rqd);
outFreePages:
	__free_pages(pages, OCBWT_BIOPAGE_ALLOC_ORDER);
outPutBIO:
	bio_put(bio);
	return ret;
}

static int ocbwt_writer_fn(void *data)
{
	struct per_readerwriter_info *wi = data;
	int ret;

	atomic64_set(&wi->finish_counter, 0);
	atomic_set(&wi->inflight_requests, 0);
	wi->wc_blk = wi->wc_lun = wi->wc_pg = wi->wc_pln = wi->wc_sec = 0;
	//pr_notice("Writer %u initialized\n", wi->writer_index);
	smp_store_release(&wi->writer_running_state, OCBWT_INITIALIZED);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();

	while (!kthread_should_stop()) {
		if (atomic_add_unless(&wi->inflight_requests, 1, OCBWT_SUBMIT_QD)) {
			ret = ocbwt_issue_write_nowait(wi);
			if (ret)
				atomic_dec(&wi->inflight_requests);
		} else {
			schedule();
		}
	}
	//pr_notice("Writer %u exit\n", wi->writer_index);
	return 0;
}

static int ocbwt_reader_fn(void *data)
{
	struct per_readerwriter_info *rwi = data;
	struct ocbw_tester *tester = rwi->ocbwt;
	int ret = 0;
	int i, k;

	rwi->rctx = kmalloc_array(OCBWT_SUBMIT_QD, sizeof(*rwi->rctx), GFP_KERNEL | __GFP_ZERO);
	if (!rwi->rctx) {
		pr_err("%s, can't allocate rctx\n", __func__);
		ret = -ENOMEM;
		goto errout;
	}

	for (i = 0; i < OCBWT_SUBMIT_QD; i++) {
		struct ocbwt_r_ctx *rctx = &rwi->rctx[i];
		struct page *pgs = rctx->pages =
				alloc_pages(GFP_KERNEL, OCBWT_BIOPAGE_ALLOC_ORDER);
		struct bio *bio = rctx->bio =
				bio_alloc(GFP_KERNEL, OCBWT_BIO_NRVEC);
		struct nvm_rq *rqd = &rctx->rqd;
		unsigned long pfn;

		if (!pgs || !bio) {
			pr_err("%s, can't allocate pages/bio\n", __func__);
			ret = -ENOMEM;
			goto errout2;
		}
		bio->bi_iter.bi_sector = 0;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		pfn = page_to_pfn(pgs);
		for (k = 0; k < OCBWT_BIOPAGE_NUM; k++) {
			struct page *page;

			page = pfn_to_page(pfn);
			bio_add_page(bio, page, PAGE_SIZE, 0);
			pfn++;
		}

		rqd->bio = bio;
		rqd->meta_list = nvm_dev_dma_alloc(tester->dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
		if (!rqd->meta_list) {
			pr_err("%s, can't allocate meta_list\n", __func__);
			ret = -ENOMEM;
			goto errout2;
		}
		rqd->opcode = NVM_OP_PREAD;
		rqd->nr_ppas = OCBWT_BIOPAGE_NUM;
		rqd->dev = tester->dev;
		rqd->flags = tester->plane_mode >> 1 | NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
		rqd->private = rwi;
		rqd->end_io = ocbwt_end_io_read;
		if (rqd->nr_ppas == 1) {
			rqd->ppa_list = &rqd->ppa_addr;
		} else {
			rqd->ppa_list = rqd->meta_list + ocmbt_dma_meta_size;
			rqd->dma_ppa_list = rqd->dma_meta_list + ocmbt_dma_meta_size;
		}
		rqd->ppa_status = rqd->error = 0;

		rctx->saved_iter = rctx->bio->bi_iter;
		WRITE_ONCE(rctx->status, 0);
	}

	atomic64_set(&rwi->r_finish_counter, 0);
	rwi->rc_blk = rwi->rc_lun = rwi->rc_pg = rwi->rc_pln = rwi->rc_sec = 0;
	smp_store_release(&rwi->reader_running_state, OCBWT_INITIALIZED);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();

	while (!kthread_should_stop()) {
		ocbwt_issue_read_requests(rwi);
		schedule();
	}
	//pr_notice("Writer %u exit\n", wi->writer_index);
	for (i = 0; i < OCBWT_SUBMIT_QD; i++) {
retry:
		if (rwi->rctx[i].status) {
			schedule();
			goto retry;
		}
	}
	for (i = 0; i < OCBWT_SUBMIT_QD; i++) {
		struct ocbwt_r_ctx *rctx = &rwi->rctx[i];
		struct nvm_rq *rqd = &rctx->rqd;

		__free_pages(rctx->pages, OCBWT_BIOPAGE_ALLOC_ORDER);
		bio_put(rctx->bio);
		nvm_dev_dma_free(tester->dev->parent, rqd->meta_list, rqd->dma_meta_list);
	}
errout2:
	kfree(rwi->rctx);
errout:
	return ret;
}

static ssize_t ocbwt_proc_write(struct file *file,
						const char __user *buffer,
						size_t count, loff_t *ppos)
{
	char usrCommand[512];
	struct ocbw_tester *tester = global_tester;
	int ret;
	unsigned int nr_chnls = tester->oc_channels;
	int i;

	ret = copy_from_user(usrCommand, buffer, count);
	switch(usrCommand[0]) {
	case 'w':
		for (i = 0; i < nr_chnls; i++)
			wake_up_process(tester->pwi[i].writer_ts);
		break;
	case 'r':
		for (i = 0; i < nr_chnls; i++)
			wake_up_process(tester->pwi[i].reader_ts);
		break;
	}

	return count;
}

static void ocbwt_fill_status(struct ocbw_tester *tester, void *ocbwt_status)
{
	struct ocbwt_global_status *gs = ocbwt_status;
	struct ocbwt_pch_status *ch_array = ocbwt_status + sizeof(struct ocbwt_global_status);
	struct ocbwt_pch_status *cs;
	unsigned int i, nr_chnls;
	struct per_readerwriter_info *wi;

	nr_chnls = gs->nr_chnls = tester->oc_channels;
	for (i = 0; i < nr_chnls; i++) {
		cs = &ch_array[i];
		wi = &tester->pwi[i];
		cs->finished = atomic64_read(&wi->finish_counter);
		cs->inflight = atomic_read(&wi->inflight_requests);
		cs->r_finished = atomic64_read(&wi->r_finish_counter);
	}
}

static ssize_t ocbwt_proc_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos)
{
	struct ocbw_tester *tester = global_tester;
	unsigned int status_size = global_tester->status_size;
	void *ocbwt_status;
	int ret;

	ocbwt_status = kmalloc(status_size, GFP_KERNEL);
	if (!ocbwt_status)
		return 0;

	ocbwt_fill_status(tester, ocbwt_status);
	if (count >= status_size)
		ret = copy_to_user(buffer, ocbwt_status, status_size);
	else
		ret = copy_to_user(buffer, ocbwt_status, count);
	kfree(ocbwt_status);
	if (ret)
		return EFAULT;
	return (count >= status_size)?status_size:count;
}

static const struct file_operations ocbwt_proc_fops = {
  .owner = THIS_MODULE,
  .write = ocbwt_proc_write,
  .read = ocbwt_proc_read,
};


void tester_print_geo(struct nvm_geo *geo) {
	pr_notice("-----tester_print_geo---------\n");
	pr_notice("chnls=0x%x,all_luns=0x%x,nrluns=0x%x,nr_chks=0x%x\n",geo->nr_chnls,geo->all_luns,geo->nr_luns,geo->nr_chks);
	pr_notice("secsize=0x%x,oobsize=0x%x,mccap=0x%x\n",geo->sec_size,geo->oob_size,geo->mccap);
	pr_notice("secPerchk=0x%x,secPerLun=0x%x\n",geo->sec_per_chk,geo->sec_per_lun);
	pr_notice("wsmin=0x%x,wsopt=0x%x,wsseq=0x%x,wsperchk=0x%x\n",geo->ws_min,geo->ws_opt,geo->ws_seq,geo->ws_per_chk);
	pr_notice("max_rq_size=0x%x,op=0x%x\n",geo->max_rq_size,geo->op);
	pr_notice("(choff=0x%x,chlen=0x%x)\n\t(lunoff=0x%x,lunlen=0x%x)\n\t(plnoff=0x%x,plnlen=0x%x)\n\t(blkoff=0x%x,blklen=0x%x)\n\t(pgoff=0x%x,pglen=0x%x)\n\t(secoff=0x%x,seclen=0x%x)\n",
		geo->ppaf.ch_offset,geo->ppaf.ch_len,
		geo->ppaf.lun_offset,geo->ppaf.lun_len,
		geo->ppaf.pln_offset,geo->ppaf.pln_len,
		geo->ppaf.blk_offset,geo->ppaf.blk_len,
		geo->ppaf.pg_offset,geo->ppaf.pg_len,
		geo->ppaf.sect_offset,geo->ppaf.sect_len);
	pr_notice("planeMode=0x%x,nr_planes=0x%x,secPerPg=0x%x,secPerPl=0x%x\n",geo->plane_mode,geo->nr_planes,geo->sec_per_pg,geo->sec_per_pl);
}


static void *tester_init(struct nvm_tgt_dev *dev, struct gendisk **ptdisk,
							struct nvm_ioctl_create *create)
{
	struct ocbw_tester *tester;
	int i;
	struct nvm_geo *geo = &dev->geo;
	int ret;
	unsigned int nr_chnls;
	struct per_readerwriter_info *wi;
	char tsname[32];
	struct gendisk *fake_disk;

	fake_disk = kmalloc(sizeof(*fake_disk), GFP_KERNEL);
	if (!fake_disk)
		return ERR_PTR(-ENOMEM);	

	strlcpy(fake_disk->disk_name, create->tgtname, sizeof(fake_disk->disk_name));
	fake_disk->private_data = tester = global_tester =
						kzalloc(sizeof(*tester), GFP_KERNEL);
	if (!tester) {
		ret = -ENOMEM;
		goto outFreeFakeDisk;
	}

	tester->dev = dev;
	tester->fake_disk = fake_disk;
	tester->oc_channels = nr_chnls = geo->nr_chnls;
	tester->nr_luns = geo->nr_luns;
	tester->nr_planes = geo->nr_planes;
	tester->nr_blks = geo->nr_chks;
	tester->pgs_per_blk = geo->sec_per_chk/(geo->sec_per_pg * geo->nr_planes);
	tester->sec_per_page = geo->sec_per_pg;
	tester->plane_mode = geo->plane_mode;
	tester->status_size = sizeof(struct ocbwt_global_status) +
									nr_chnls * sizeof(struct ocbwt_pch_status);

	tester_print_geo(geo);

	tester->pwi = kmalloc_array(nr_chnls, sizeof(*tester->pwi), GFP_KERNEL | __GFP_ZERO);
	if (!tester->pwi) {
		ret = -ENOMEM;
		goto outFreeTester;
	}

	for (i = 0; i < nr_chnls; i++) {
		wi = &tester->pwi[i];
		wi->ocbwt = tester;
		wi->writer_index = i;
		wi->reader_running_state =
			wi->writer_running_state =
					OCBWT_UNINITIALIZED;

		sprintf(tsname, "ocbwt_w_%u", i);
		wi->writer_ts = kthread_create(ocbwt_writer_fn, wi, tsname);
		if (IS_ERR(wi->writer_ts)) {
			ret = -ENOMEM;
			goto outFreeReaderWriters;
		}

		sprintf(tsname, "ocbwt_r_%u", i);
		wi->reader_ts = kthread_create(ocbwt_reader_fn, wi, tsname);
		if (IS_ERR(wi->reader_ts)) {
			ret = -ENOMEM;
			goto outFreeReaderWriters;
		}
	}
	barrier();
	for (i = 0; i < nr_chnls; i++) {
		wake_up_process(tester->pwi[i].writer_ts);
		wake_up_process(tester->pwi[i].reader_ts);
	}
	for (i = 0; i < nr_chnls; i++) {
		wi = &tester->pwi[i];
		while (OCBWT_INITIALIZED != READ_ONCE(wi->writer_running_state))
			schedule();
		while (OCBWT_INITIALIZED != READ_ONCE(wi->reader_running_state))
			schedule();
	}

	proc_create("ocbwt", 0, NULL, &ocbwt_proc_fops);

	*ptdisk = fake_disk;
	barrier();
	pr_notice("ocbwt init finished\n");

	return tester;

	remove_proc_entry("ocbwt", NULL);
outFreeReaderWriters:
	for (i = 0; i < nr_chnls; i++) {
		wi = &tester->pwi[i];
		if (wi->writer_ts && !IS_ERR(wi->writer_ts))
			kthread_stop(wi->writer_ts);
		if (wi->reader_ts && !IS_ERR(wi->reader_ts))
			kthread_stop(wi->reader_ts);
	}
outFreeTester:
	kfree(tester);
outFreeFakeDisk:
	kfree(fake_disk);
	return ERR_PTR(ret);
}

static void tester_exit(void *private)
{
	struct ocbw_tester *tester = private;
	unsigned int chnls = tester->oc_channels;
	unsigned int i;
	struct gendisk *fake_disk = tester->fake_disk;

	remove_proc_entry("ocbwt", NULL);
	global_tester = NULL;

	for (i = 0; i < chnls; i++) {
		kthread_stop(tester->pwi[i].writer_ts);
		kthread_stop(tester->pwi[i].reader_ts);
	}

	for (i = 0; i < chnls; i++) {
		while (0 != atomic_read(&tester->pwi[i].inflight_requests))
			schedule();
	}

	kfree(tester);
	kfree(fake_disk);
	pr_notice("ocbwt exit finished\n");
}


/* physical block device target */
static struct nvm_tgt_type tt_ocbwt = {
	.name		= "ocbwt",
	.version	= {1, 0, 0},
	.init		= tester_init,
	.exit		= tester_exit,
	.owner		= THIS_MODULE,
};

static int __init ocbwtester_init(void)
{
	int ret;

	ret = nvm_register_tgt_type(&tt_ocbwt);

	pr_notice("rGen module loaded,%d\n",ret);

	return ret;
}

static void ocbwtester_exit(void)
{
	nvm_unregister_tgt_type(&tt_ocbwt);
	pr_notice("rGen module removed\n");
}

module_init(ocbwtester_init);
module_exit(ocbwtester_exit);
MODULE_AUTHOR("Hongwei Qin <glqhw@qq.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Bandwidth Tester for Open-Channel SSDs");

