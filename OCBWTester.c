#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/uuid.h>
#include <linux/cpumask.h>
#include <linux/lightnvm.h>
#include <linux/bitmap.h>
#include <linux/proc_fs.h>

enum {
	OCBWT_UNINITIALIZED = 0,
	OCBWT_INITIALIZED,
};

struct per_writer_info {
	/* Writer task struct */
	struct task_struct *writer_ts;

	/* Parameters for writers. */
	struct ocbw_tester *ocbwt;
	unsigned int writer_index;
	volatile int running_state;

	/* Variables that used by the writer. */
	atomic64_t counter;
};

struct ocbw_tester {
	struct nvm_tgt_dev *dev;
	struct gendisk *fake_disk;
	unsigned int oc_channels;
	int nr_luns;
	int nr_planes;
	struct per_writer_info *pwi;
};


static int ocbwt_writer_fn(void *data)
{
	struct per_writer_info *wi = data;
	unsigned int writer_index = wi->writer_index;

	atomic64_set(&wi->counter, 0);
	pr_notice("Writer %u initialized\n", writer_index);
	smp_store_release(&wi->running_state, OCBWT_INITIALIZED);
	
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	pr_notice("Writer %u exit\n", writer_index);
	return 0;
}


static const struct file_operations ocbwt_proc_fops = {
  .owner = THIS_MODULE,
  //.write = rGen_write,
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
	fake_disk->private_data = tester = kzalloc(sizeof(*tester), GFP_KERNEL);
	if (!tester) {
		ret = -ENOMEM;
		goto outFreeFakeDisk;
	}

	tester->dev = dev;
	tester->fake_disk = fake_disk;
	tester->oc_channels = nr_chnls = geo->nr_chnls;
	tester->nr_luns = geo->nr_luns;
	tester->nr_planes = geo->nr_planes;

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

	for (i = 0; i < chnls; i++)
		kthread_stop(tester->pwi[i].writer_ts);

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

