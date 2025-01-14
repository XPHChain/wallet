import React from "react";

import { useSlider } from ".";

interface SliderProperties {
	children?: any;
	data?: any;
	options?: any;
	className?: string;
	paginationPosition?: "bottom-center" | "top-right";
}

export const Slider = ({
	children,
	data,
	options,
	className,
	paginationPosition = "bottom-center",
}: SliderProperties) => {
	const { showPagination, containerHeight, slideStyles, wrapperRef } = useSlider({
		container: ".slide-container",
		data,
		options,
		paginationPosition,
	});

	const renderChildNode = (data: any, index: number) => {
		if (typeof children === "function") {
			return children(data, index);
		}
		return <div />;
	};

	return (
		<div className="relative">
			{showPagination && paginationPosition === "top-right" && (
				<div className="flex absolute right-0 -top-12 items-center space-x-2 w-auto h-6 swiper-pagination" />
			)}

			<div
				className="overflow-hidden -mb-8 list-none px-4.5 -mx-4.5 slide-container"
				style={{ height: `${containerHeight}px` }}
			>
				<div className={`h-full swiper-wrapper important:z-0 ${className || ""}`} ref={wrapperRef}>
					{data.map((item: any, index: number) => (
						<div className="swiper-slide" key={index} style={slideStyles}>
							{{ ...renderChildNode(item, index) }}
						</div>
					))}
				</div>

				{showPagination && paginationPosition === "bottom-center" && (
					<div className="flex justify-center items-center h-6 swiper-pagination important:bottom-8 important:z-0" />
				)}
			</div>
		</div>
	);
};
