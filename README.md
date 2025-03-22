# Разрешение предупреждения Svace относительно кода в linux-kernel

## Введение

[__Linux-kernel__](https://github.com/torvalds/linux) --- проект на очень много строк кода (~20 млн), который сопровождается группой профессиональных программистов.

Но иногда случается так, что в linux-kernel пропускается код, который может содержать незамеченные баги/уязвимости.

Причин возникновения таких проблем может быть много, но целью этого README является не их перечисление, а их решение.

Одним из методов решения такой проблемы является прогонка кода, который готовится к попаданию в ядро, через статический анализатор (например [__Svace__](https://www.ispras.ru/technologies/svace/])).

Статический анализатор, в свою очередь, может выдать предупреждение на вполне себе рабочий код.

В данном README показан путь анализа такого предупреждения.

## Начало анализа
Относительно строки [740 файла drivers/media/platform/nvidia/tegra-vde/h264.c](https://elixir.bootlin.com/linux/v6.1.129/source/drivers/media/platform/nvidia/tegra-vde/h264.c#L740) (функция `int tegra_vde_h264_setup_frame(...)`):
```С
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
```С
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

	if (id == 0) {
		frame_num = h->decode_params->frame_num;

		if (h->decode_params->nal_ref_idc)
			flags |= FLAG_REFERENCE;
	} else {
		frame_num = b->refs[ref_id].frame_num;
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

Посмотрим, где происходит вызов этой функции и с какими аргументами.



