/* Align and pad the shared debug counter section to the page size */
SECTIONS {
	. = ALIGN(4096);
        shared_debug_counter_start = .;
	.shared_debug_counter : { *(.shared_debug_counter) }
        shared_debug_counter_end = .;
	. = ALIGN(4096);
}
INSERT AFTER .data;
