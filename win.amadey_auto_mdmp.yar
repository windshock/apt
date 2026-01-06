rule win_amadey_auto_mdmp {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com (modified for mdmp use)"
        date = "2026-01-06"
        version = "1"
        description = "Detects win.amadey (mdmp-friendly variant)."
        info = "Based on win.amadey_auto.yar; filesize constraint removed to allow mdmp chunk scanning."
        tool = "yara-signator v0.6.0 (base rule) + local modifications"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"

    strings:
        $sequence_0 = { 837e1410 7202 8b3e 8a0402 88040f 41 }
        $sequence_1 = { 83f802 7427 e8???????? 83f810 }
        $sequence_2 = { 83c408 83ec18 8bf4 83ec18 8bcc 68???????? }
        $sequence_3 = { 8b10 ff7010 837d4c10 8d4d38 8b7548 0f434d38 }
        $sequence_4 = { 83caff 8b4508 8bc8 83781410 7202 8b08 }
        $sequence_5 = { 83f801 7431 e8???????? 83f802 7427 }
        $sequence_6 = { 8bcc 68???????? e8???????? 8d4db4 e8???????? }
        $sequence_7 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
        $sequence_8 = { 68???????? e8???????? 8d4d98 e8???????? 83c418 }
        $sequence_9 = { 722f 8b8d78feffff 42 8bc1 81fa00100000 }
        $sequence_10 = { 8985f4fbffff 8b85ecfbffff c1e002 8985f0fbffff 8b85f4fbffff 890424 e8???????? }
        $sequence_11 = { e8???????? c7442404???????? 8d85e8feffff 890424 e8???????? 8d85e8feffff 890424 }
        $sequence_12 = { c70424???????? e8???????? 8b45fc 89442408 c7442404???????? }
        $sequence_13 = { 8d85f8fdffff 890424 e8???????? c744240800020000 c744240400000000 }
        $sequence_14 = { 50 68???????? 83ec18 8bcc 68???????? }
        $sequence_15 = { e8???????? 8985f4dfffff 83bdf4dfffff00 742c }
        $sequence_16 = { 8945f4 eb05 ff4508 eba7 8b45f4 }
        $sequence_17 = { 890424 e8???????? 89442404 8d85f8f9ffff 890424 e8???????? }
        $sequence_18 = { eb0a c705????????04000000 83bd5cffffff06 7525 83bd60ffffff02 }
        $sequence_19 = { 56 57 8b3d???????? 83ec18 }
        $sequence_20 = { 51 e8???????? 83c408 8b9514feffff }

    condition:
        // mdmp chunks are often larger than the original rule's filesize cap (908,288 bytes),
        // so we drop the size constraint for memory-dump scanning.
        7 of them
}


