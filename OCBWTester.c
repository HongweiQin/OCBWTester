#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/uuid.h>
#include <linux/cpumask.h>
#include <linux/lightnvm.h>
#include <linux/bitmap.h>
#include <linux/proc_fs.h>

#define OCBWT_SUBMIT_QD (16)
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
};

struct per_writer_info {
	/* Writer task struct */
	struct task_struct *writer_ts;

	/* Parameters for writers. */
	struct ocbw_tester *ocbwt;
	unsigned int writer_index;
	volatile int running_state;

	/* Variables that used by the writer. */
	atomic64_t finish_counter;
	atomic_t inflight_requests;
	int c_lun;
	int c_pln;
	int c_blk;
	int c_pg;
	int c_sec;
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
	struct per_writer_info *pwi;
	unsigned int status_size;
};

struct ocbw_tester *global_tester;

static struct ppa_addr ocbwt_calculate_ppa(struct ocbw_tester *tester,
									struct per_writer_info *wi)
{
	struct ppa_addr ppa = {.ppa=0};

	ppa.g.blk = wi->c_blk;
	ppa.g.pg = wi->c_pg;
	ppa.g.sec = wi->c_sec;
	ppa.g.pl = wi->c_pln;
	ppa.g.lun = wi->c_lun;
	ppa.g.ch = wi->writer_index;

	wi->c_sec++;
	if (wi->c_sec == tester->sec_per_page) {
		wi->c_sec = 0;
		wi->c_pln++;
		if (wi->c_pln == tester->nr_planes) {
			wi->c_pln = 0;
			wi->c_lun++;
			if (wi->c_lun == tester->nr_luns) {
				wi->c_lun = 0;
				wi->c_pg++;
				if (wi->c_pg == tester->pgs_per_blk) {
					wi->c_pg = 0;
					wi->c_blk++;
					if (wi->c_blk == tester->nr_blks)
						wi->c_blk = 0;
				}
			}
		}
	}
	return ppa;
}

static void ocbwt_end_io_write(struct nvm_rq *rqd)
{
	struct per_writer_info *wi = rqd->private;
	struct bio *bio = rqd->bio;

	if (rqd->error) {
		pr_err("Write error\n");
	}

	//pr_notice("Finish rqd wi %u\n", wi->writer_index);
	atomic64_inc(&wi->finish_counter);
	atomic_dec(&wi->inflight_requests);

	nvm_dev_dma_free(wi->ocbwt->dev->parent, rqd->meta_list, rqd->dma_meta_list);
	kfree(rqd);
	__free_pages(bio_first_page_all(bio), OCBWT_BIOPAGE_ALLOC_ORDER);
	bio_put(bio);
}

static int ocbwt_issue_write_nowait(struct per_writer_info *wi)
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
		rqd->ppa_list[i] = ocbwt_calculate_ppa(tester, wi);

	//pr_notice("%s, ch[%u] ppa=0x%llx\n",
	//		__func__, wi->writer_index, rqd->ppa_list[0].ppa);

	return nvm_submit_io(tester->dev, rqd);

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
	struct per_writer_info *wi = data;

	atomic64_set(&wi->finish_counter, 0);
	atomic_set(&wi->inflight_requests, 0);
	wi->c_blk = wi->c_lun = wi->c_pg = wi->c_pln = wi->c_sec = 0;
	//pr_notice("Writer %u initialized\n", wi->writer_index);
	smp_store_release(&wi->running_state, OCBWT_INITIALIZED);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();

	while (!kthread_should_stop()) {
		if (atomic_add_unless(&wi->inflight_requests, 1, OCBWT_SUBMIT_QD))
			ocbwt_issue_write_nowait(wi);
		else
			schedule();
	}
	//pr_notice("Writer %u exit\n", wi->writer_index);
	return 0;
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
	case 'g':
		for (i = 0; i < nr_chnls; i++)
			wake_up_process(tester->pwi[i].writer_ts);
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
	struct per_writer_info *wi;

	nr_chnls = gs->nr_chnls = tester->oc_channels;
	for (i = 0; i < nr_chnls; i++) {
		cs = &ch_array[i];
		wi = &tester->pwi[i];
		cs->finished = atomic64_read(&wi->finish_counter);
		cs->inflight = atomic_read(&wi->inflight_requests);
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
	struct per_writer_info *wi;
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
		wi->running_state = OCBWT_UNINITIALIZED;

		sprintf(tsname, "ocbwt_%u", i);
		wi->writer_ts = kthread_create(ocbwt_writer_fn, wi, tsname);
		if (IS_ERR(wi->writer_ts)) {
			ret = -ENOMEM;
			goto outFreeWriters;
		}
	}
	barrier();
	for (i = 0; i < nr_chnls; i++)
		wake_up_process(tester->pwi[i].writer_ts);
	for (i = 0; i < nr_chnls; i++) {
		wi = &tester->pwi[i];
		while (OCBWT_INITIALIZED != READ_ONCE(wi->running_state))
			schedule();
	}

	proc_create("ocbwt", 0, NULL, &ocbwt_proc_fops);

	*ptdisk = fake_disk;
	barrier();
	pr_notice("ocbwt init finished\n");

	return tester;

	remove_proc_entry("ocbwt", NULL);
outFreeWriters:
	for (i = 0; i < nr_chnls; i++) {
		wi = &tester->pwi[i];
		kthread_stop(wi->writer_ts);
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

	for (i = 0; i < chnls; i++)
		kthread_stop(tester->pwi[i].writer_ts);

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

