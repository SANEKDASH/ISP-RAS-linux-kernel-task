# Разрешение предупреждения Svace относительно кода в linux-kernel

## Введение

[__Linux-kernel__](https://github.com/torvalds/linux) --- проект на очень много строк кода (~20 млн), который сопровождается группой профессиональных программистов.

Но иногда случается так, что в linux-kernel пропускается код, который может содержать незамеченные баги/уязвимости.

Причин возникновения таких проблем может быть много, но целью этого README является не их перечисление, а их решение.

Одним из методов решения такой проблемы является прогонка кода, который готовится к попаданию в ядро, через статический анализатор (например [__Svace__](https://www.ispras.ru/technologies/svace/])).

Статический анализатор, в свою очередь, может выдать предупреждение на вполне себе рабочий код, но может указать и на баг. Тогда перед разработчиком стоит задача разобраться с тем,
является ли предупреждение ложным или в коде реально есть проблемы.

В данном README показан путь анализа такого предупреждения.

## Начало анализа

> [!NOTE]
> Версия ядра, с которым ведется работа - 6.1.129

Относительно строки [740 файла drivers/media/platform/nvidia/tegra-vde/h264.c](https://elixir.bootlin.com/linux/v6.1.129/source/drivers/media/platform/nvidia/tegra-vde/h264.c#L740) (функция `int tegra_vde_h264_setup_frame(...)`):
```c
...
} else {
    frame_num = b->refs[ref_id].frame_num;
}
...
```
Svace дал следующее предупреждение:
```
After having been assigned to a NULL value at h264.c:793, pointer '0' is
passed as 3rd parameter in call to function 'tegra_vde_h264_setup_frame'
at h264.c:793, where it is dereferenced at h264.c:734.
```
Нам нужно оценить является ли это предупреждение ложным, или в коде действительно
есть проблема.

Посмотрим на эту функцию целиком:
```c
static int tegra_vde_h264_setup_frame(struct tegra_ctx *ctx,
				      struct tegra_vde_h264_decoder_ctx *h264,
				      struct v4l2_h264_reflist_builder *b,
				      struct vb2_buffer *vb,
				      unsigned int ref_id,
				      unsigned int id)
{
	struct v4l2_pix_format_mplane *pixfmt = &ctx->decoded_fmt.fmt.pix_mp;
	struct tegra_m2m_buffer *tb = vb_to_tegra_buf(vb);
	struct tegra_ctx_h264 *h = &ctx->h264;
	struct tegra_vde *vde = ctx->vde;
	struct device *dev = vde->dev;
	unsigned int cstride, lstride;
	unsigned int flags = 0;
	size_t lsize, csize;
	int err, frame_num;

	lsize = h264->pic_width_in_mbs * 16 * h264->pic_height_in_mbs * 16;
	csize = h264->pic_width_in_mbs *  8 * h264->pic_height_in_mbs *  8;
	lstride = pixfmt->plane_fmt[0].bytesperline;
	cstride = pixfmt->plane_fmt[1].bytesperline;

	err = tegra_vde_validate_vb_size(ctx, vb, 0, lsize);
	if (err)
		return err;

	err = tegra_vde_validate_vb_size(ctx, vb, 1, csize);
	if (err)
		return err;

	err = tegra_vde_validate_vb_size(ctx, vb, 2, csize);
	if (err)
		return err;

	if (!tb->aux || tb->aux->size < csize) {
		dev_err(dev, "Too small aux size %zd, should be at least %zu\n",
			tb->aux ? tb->aux->size : -1, csize);
		return -EINVAL;
	}

	if (id == 0) { // Условие, не выполнение которого ведет к ошибке
		frame_num = h->decode_params->frame_num;

		if (h->decode_params->nal_ref_idc)
			flags |= FLAG_REFERENCE;
	} else {
		frame_num = b->refs[ref_id].frame_num; // Интересующая нас строка
	}

	if (tb->b_frame)
		flags |= FLAG_B_FRAME;

	vde->frames[id].flags = flags;
	vde->frames[id].y_addr = tb->dma_addr[0];
	vde->frames[id].cb_addr = tb->dma_addr[1];
	vde->frames[id].cr_addr = tb->dma_addr[2];
	vde->frames[id].aux_addr = tb->aux->dma_addr;
	vde->frames[id].frame_num = frame_num & 0x7fffff;
	vde->frames[id].luma_atoms_pitch = lstride / VDE_ATOM;
	vde->frames[id].chroma_atoms_pitch = cstride / VDE_ATOM;

	return 0;
}
```

Видим, что, если аргумент `id` этой функции равен 0, выполнение проблемной строки, о которой было сказано выше, не происходит.

Посмотрим, где происходит вызов этой функции и с какими аргументами.

При поиске идентификатора `tegra_vde_h264_setup_frame` в Elixir Bootlin видим два референса в функции `tegra_vde_h264_setup_frames`:
```c
static int tegra_vde_h264_setup_frames(struct tegra_ctx *ctx,
				       struct tegra_vde_h264_decoder_ctx *h264)
{
	struct vb2_v4l2_buffer *src = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	struct vb2_v4l2_buffer *dst = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);
	const struct v4l2_h264_dpb_entry *dpb = ctx->h264.decode_params->dpb;
	struct tegra_m2m_buffer *tb = vb_to_tegra_buf(&dst->vb2_buf);
	struct tegra_ctx_h264 *h = &ctx->h264;
	struct v4l2_h264_reflist_builder b;
	struct v4l2_h264_reference *dpb_id;
	struct h264_reflists reflists;
	struct vb2_buffer *ref;
	unsigned int i;
	int err;

	/*
	 * Tegra hardware requires information about frame's type, assuming
	 * that frame consists of the same type slices. Userspace must tag
	 * frame's type appropriately.
	 *
	 * Decoding of a non-uniform frames isn't supported by hardware and
	 * require software preprocessing that we don't implement. Decoding
	 * is expected to fail in this case. Such video streams are rare in
	 * practice, so not a big deal.
	 *
	 * If userspace doesn't tell us frame's type, then we will try decode
	 * as-is.
	 */
	v4l2_m2m_buf_copy_metadata(src, dst, true);

	if (h->decode_params->flags & V4L2_H264_DECODE_PARAM_FLAG_BFRAME)
		tb->b_frame = true;
	else
		tb->b_frame = false;

// Интересующий нас вызов, где аргумент b = NULL
	err = tegra_vde_h264_setup_frame(ctx, h264, NULL, &dst->vb2_buf, 0,
					 h264->dpb_frames_nb++);
	if (err)
		return err;

	if (!(h->decode_params->flags & (V4L2_H264_DECODE_PARAM_FLAG_PFRAME |
					 V4L2_H264_DECODE_PARAM_FLAG_BFRAME)))
		return 0;

	v4l2_h264_init_reflist_builder(&b, h->decode_params, h->sps, dpb);

	if (h->decode_params->flags & V4L2_H264_DECODE_PARAM_FLAG_BFRAME) {
		v4l2_h264_build_b_ref_lists(&b, reflists.b0, reflists.b1);
		dpb_id = reflists.b0;
	} else {
		v4l2_h264_build_p_ref_list(&b, reflists.p);
		dpb_id = reflists.p;
	}

	for (i = 0; i < b.num_valid; i++) {
		int dpb_idx = dpb_id[i].index;

		ref = get_ref_buf(ctx, dst, dpb_idx);

		err = tegra_vde_h264_setup_frame(ctx, h264, &b, ref, dpb_idx,
						 h264->dpb_frames_nb++);
		if (err)
			return err;

		if (b.refs[dpb_idx].top_field_order_cnt < b.cur_pic_order_count)
			h264->dpb_ref_frames_with_earlier_poc_nb++;
	}

	return 0;
}
```

В самом деле видно, что передается NULL. Но мы видим, что в качестве аргумента `id` функции
`tegra_vde_h264_setup_frame` передается `h264->dpb_frames_nb++`.
Теперь нам нужно узнать на что указывает `h264`, и какие данные в нем находятся во время этого вызова.

Для начала, посмотрим на поля структуры `tegra_vde_h264_decoder_ctx`:
```c
struct tegra_vde_h264_decoder_ctx {
	unsigned int dpb_frames_nb; // Интересующее нас поле
	unsigned int dpb_ref_frames_with_earlier_poc_nb;
	unsigned int baseline_profile;
	unsigned int level_idc;
	unsigned int log2_max_pic_order_cnt_lsb;
	unsigned int log2_max_frame_num;
	unsigned int pic_order_cnt_type;
	unsigned int direct_8x8_inference_flag;
	unsigned int pic_width_in_mbs;
	unsigned int pic_height_in_mbs;
	unsigned int pic_init_qp;
	unsigned int deblocking_filter_control_present_flag;
	unsigned int constrained_intra_pred_flag;
	unsigned int chroma_qp_index_offset;
	unsigned int pic_order_present_flag;
	unsigned int num_ref_idx_l0_active_minus1;
	unsigned int num_ref_idx_l1_active_minus1;
};
```

Теперь смотрим, где происходит вызов функции `tegra_vde_h264_setup_frames`.

Elixir Bootlin сообщает, что вызов `tegra_vde_h264_setup_frames` происходит в единственной функции, имя которой --- `tegra_vde_h264_setup_context`:
```c
static int tegra_vde_h264_setup_context(struct tegra_ctx *ctx,
					struct tegra_vde_h264_decoder_ctx *h264)
{
	struct tegra_ctx_h264 *h = &ctx->h264;
	struct tegra_vde *vde = ctx->vde;
	struct device *dev = vde->dev;
	int err;

	memset(h264, 0, sizeof(*h264)); // Все поля структуры, на которую
					// указывает h264 равны 0

	memset(vde->frames, 0, sizeof(vde->frames));

	tegra_vde_prepare_control_data(ctx, V4L2_CID_STATELESS_H264_DECODE_PARAMS);
	tegra_vde_prepare_control_data(ctx, V4L2_CID_STATELESS_H264_SPS);
	tegra_vde_prepare_control_data(ctx, V4L2_CID_STATELESS_H264_PPS);

	/* CABAC unsupported by hardware, requires software preprocessing */
	if (h->pps->flags & V4L2_H264_PPS_FLAG_ENTROPY_CODING_MODE)
		return -EOPNOTSUPP;

	if (h->decode_params->flags & V4L2_H264_DECODE_PARAM_FLAG_FIELD_PIC)
		return -EOPNOTSUPP;

	if (h->sps->profile_idc == 66)
		h264->baseline_profile = 1;

	if (h->sps->flags & V4L2_H264_SPS_FLAG_DIRECT_8X8_INFERENCE)
		h264->direct_8x8_inference_flag = 1;

	if (h->pps->flags & V4L2_H264_PPS_FLAG_CONSTRAINED_INTRA_PRED)
		h264->constrained_intra_pred_flag = 1;

	if (h->pps->flags & V4L2_H264_PPS_FLAG_DEBLOCKING_FILTER_CONTROL_PRESENT)
		h264->deblocking_filter_control_present_flag = 1;

	if (h->pps->flags & V4L2_H264_PPS_FLAG_BOTTOM_FIELD_PIC_ORDER_IN_FRAME_PRESENT)
		h264->pic_order_present_flag = 1;

	h264->level_idc				= to_tegra_vde_h264_level_idc(h->sps->level_idc);
	h264->log2_max_pic_order_cnt_lsb	= h->sps->log2_max_pic_order_cnt_lsb_minus4 + 4;
	h264->log2_max_frame_num		= h->sps->log2_max_frame_num_minus4 + 4;
	h264->pic_order_cnt_type		= h->sps->pic_order_cnt_type;
	h264->pic_width_in_mbs			= h->sps->pic_width_in_mbs_minus1 + 1;
	h264->pic_height_in_mbs			= h->sps->pic_height_in_map_units_minus1 + 1;

	h264->num_ref_idx_l0_active_minus1	= h->pps->num_ref_idx_l0_default_active_minus1;
	h264->num_ref_idx_l1_active_minus1	= h->pps->num_ref_idx_l1_default_active_minus1;
	h264->chroma_qp_index_offset		= h->pps->chroma_qp_index_offset & 0x1f;
	h264->pic_init_qp			= h->pps->pic_init_qp_minus26 + 26;

	err = tegra_vde_h264_setup_frames(ctx, h264); // Интересующий нас вызов.
						      // До сих пор:
                                                      // h264->dpb_frames_nb = 0
	if (err)
		return err;

	err = tegra_vde_validate_h264_ctx(dev, h264);
	if (err)
		return err;

	return 0;
}
```
Таким образом мы выяснили, что  `h264->dpb_frames_nb` имеет значение 0 при вызове функции `tegra_vde_h264_setup_frames`.
Так же можем видеть, что на всем пути к строке, о которой мы имеем предупреждение от Svace,
значение `h264->dpb_frames_nb` остается равным 0, а [после выполнения этого вызова](https://elixir.bootlin.com/linux/v6.1.129/source/drivers/media/platform/nvidia/tegra-vde/h264.c#L793)
станет равным 1. Соответственно [это условие](https://elixir.bootlin.com/linux/v6.1.129/source/drivers/media/platform/nvidia/tegra-vde/h264.c#L734) будет выполнено, а значит перехода по нулевому адресу, о котором нам сообщил Svace не будет.

## Вывод
Данное предупреждение оказалось ложным.
Но этот факт не уменьшает вероятности попадания в __linux-kernel__
кода, содержащего баги/уязвимости, потому что код в основном пишут люди, а людям свойственно ошибаться.
