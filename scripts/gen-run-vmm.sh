#!/bin/bash
# Generate reference values, a DTB and a scripts containing the VMM command

set -eu

use_virtconsole=true
use_edk2=false
use_direct_kernel=true
use_initrd=true
use_rme=true
use_net_tap=false
verbose=false
separate_console=false
vmm=qemu

gen_token=false

: ${CFG:=gen-run-vmm.cfg}

# Try to find a config file containing KERNEL and INITRD
for cfg in $CFG /usr/share/realm-token/gen-run-vmm.cfg; do
    if [ -f "$cfg" ]; then
        source "$cfg"
        break;
    fi
done

# Paths for the generator
: ${KERNEL:?}
: ${INITRD:?}
: ${EDK2_DIR:?}

: ${OUTPUT_SCRIPT_DIR:=.}
: ${OUTPUT_DTB_DIR:=.}

: ${RVSTORE_DIR:=}
: ${CONFIGS_DIR:=/usr/share/realm-token/configs}
: ${REALM_TOKEN:=realm-token}

# Paths for the generated run script
: ${RUN_KERNEL:=guest_kernel}
: ${RUN_INITRD:=guest_initrd}
: ${RUN_EDK2_DIR:=.}
# An ext4 filesystem containing only the userspace
: ${RUN_ROOTFS:=guest_rootfs}
# A disk containing an EFI partition with the kernel and bootloader, and
# another with the userspace
: ${RUN_DISK:=guest_disk}

COMID_TEMPLATE=
CORIM_TEMPLATE=
CORIM_OUTPUT=

INPUT_RVSTORE="$RVSTORE_DIR/rv.json"

TEMP=$(getopt -o 'hvT' --long 'help,edk2,disk-boot,disk,gen-token,serial,no-rme,kvmtool,cloudhv,tap,verbose,comid-template:,corim-template:,corim-output:,extcon' -n 'gen-run-vmm' -- "$@")
if [ $? -ne 0 ]; then
    exit 1
fi

eval set -- "$TEMP"
unset TEMP
while true; do
    case "$1" in
    '--edk2')
        use_edk2=true
        ;;
    '--disk-boot')
        use_direct_kernel=false
        ;;
    '--disk')
        use_initrd=false
        ;;
    '--serial')
        use_virtconsole=false
        ;;
    '--no-rme')
        use_rme=false
        ;;
    '--kvmtool')
        vmm=kvmtool
        ;;
    '--cloudhv')
        vmm=cloud-hv
        use_net_tap=true
        ;;
    '--tap')
        use_net_tap=true
        ;;
    '--corim-template')
        CORIM_TEMPLATE="$2"
        shift
        ;;
    '--comid-template')
        COMID_TEMPLATE="$2"
        shift
        ;;
    '--corim-output')
        CORIM_OUTPUT="$2"
        gen_token=true
        shift
        ;;
    '--extcon')
        separate_console=true
        ;;
    '-v'|'--verbose')
        verbose=true
        ;;
    '-h'|'--help')
        echo "Usage: $0"
        echo "  --disk-boot     boot from disk instead of direct kernel boot"
        echo "  --disk          use disk as userspace instead of initrd"
        echo "  --edk2          used ekd2 firmware"
        echo "  --kvmtool       use kvmtool as VMM (default QEMU)"
        echo "  --cloudhv       use cloud-hypervisor as VMM"
        echo "  --no-rme        disable RME"
        echo "  --serial        use serial instead of virtconsole"
        echo "  --tap           use tap networking instead of user"
        echo "  --extcon        use a separate in+out console for the guest"
        echo "  -v --verbose    be more verbose"
        echo
        echo "  --comid-template <file.json>"
        echo "  --corim-template <file.json>"
        echo "  --corim-output <file.cbor>  Generate CoMID file containing reference values"
        exit 1
        ;;
    '--')
        shift
        break
        ;;
    *)
        echo 'Internal error!' >&2
        exit 1
        ;;
    esac
    shift
done

if [ $# -ne 0 ]; then
    echo "Unexpected argument '$1'" >&2
    exit 1
fi

if $use_edk2; then
    use_virtconsole=false
fi

declare -a CMD
declare -a KPARAMS

if $use_virtconsole; then
    KPARAMS+=(console=hvc0)
else
    KPARAMS+=(earlycon console=ttyAMA0)
fi

if ! $use_initrd; then
    KPARAMS+=(root=/dev/vda)
fi

if [ "$vmm" = "kvmtool" ]; then
    OUTPUT_SCRIPT="$OUTPUT_SCRIPT_DIR/run_kvm.sh"
    OUTPUT_DTB="$OUTPUT_DTB_DIR/kvmtool-gen.dtb"
    EDK2="$EDK2_DIR/Build/ArmVirtKvmtool-AARCH64/DEBUG_GCC5/FV/KVMTOOL_EFI.fd"

    if $use_virtconsole; then
        CMD+=(--console virtio)
    else
        CMD+=(--console serial)
    fi

    if $use_rme; then
        CMD+=(--realm --restricted_mem --sve-vl=512)
    fi

    CMD+=(
        -c 2 -m 512
        -k ${RUN_KERNEL}
        --virtio-transport pci
        --irqchip=gicv3-its
        --pmu
        --network mode=user
        #--9p /mnt/shr0,shr0
        --dtb kvmtool-gen.dtb
        --debug
    )
    if $use_initrd; then
        CMD+=(-i "$RUN_INITRD")
    else
        CMD+=(-d "$RUN_ROOTFS")
    fi

    APPEND=(-p "${KPARAMS[*]}")
elif [ "$vmm" = "cloud-hv" ]; then
    OUTPUT_SCRIPT="$OUTPUT_SCRIPT_DIR/run_cloudhv.sh"
    OUTPUT_DTB="$OUTPUT_DTB_DIR/cloudhv-gen.dtb"
    EDK2="$EDK2_DIR/Build/ArmVirtCloudHv-AARCH64/DEBUG_GCC5/FV/QEMU_EFI.fd"

    if $use_rme; then
        CMD+=(--platform "arm_rme=on,measurement_algo=sha512,personalization_value=abcd")
    fi

    if $use_virtconsole; then
        CMD+=(--console tty --serial off)
    else
        CMD+=(--console off --serial tty)
    fi

    if $use_direct_kernel; then
        CMD+=(--kernel "$RUN_KERNEL")
        if $use_initrd; then
            CMD+=(--initramfs "$RUN_INITRD")
        else
            CMD+=(--disk path="$RUN_ROOTFS")
        fi
    else
        CMD+=(--disk path="$RUN_DISK")
    fi


    if $use_edk2; then
        CMD+=(-bios "$RUN_EDK2_DIR/QEMU_EFI.fd")
    fi

    CMD+=(
        --cpus boot=2
        --memory size=512M
        --net fd=3,mac='$tapaddress'
        --dtb cloudhv-gen.dtb
        -v
    )

    APPEND=(--cmdline "${KPARAMS[*]}")
else # QEMU
    OUTPUT_SCRIPT="$OUTPUT_SCRIPT_DIR/run_qemu.sh"
    OUTPUT_DTB="$OUTPUT_DTB_DIR/qemu-gen.dtb"
    EDK2="$EDK2_DIR/Build/ArmVirtQemu-AARCH64/DEBUG_GCC5/FV/QEMU_EFI.fd"

    if $use_rme; then
        CMD+=(-M confidential-guest-support=rme0 -object rme-guest,id=rme0,measurement-algo=sha512,personalization-value=abcd)
    fi

    if $use_virtconsole; then
        CMD+=(-nodefaults)
        CMD+=(-chardev stdio,mux=on,id=virtiocon0,signal=off -device virtio-serial-pci -device virtconsole,chardev=virtiocon0 -mon chardev=virtiocon0,mode=readline)
    fi

    if $use_direct_kernel; then
        CMD+=(-kernel "$RUN_KERNEL")
        if $use_initrd; then
            CMD+=(-initrd "$RUN_INITRD")
        else
            CMD+=(-device virtio-blk-pci,drive=rootfs0)
            CMD+=(-drive format=raw,if=none,file=/tmp/guest_disk,id=rootfs0)
        fi
    else
        use_initrd=false
        CMD+=(-device virtio-blk-pci,drive=rootfs0)
        CMD+=(-drive format=raw,if=none,file=/tmp/guest_disk,id=rootfs0)
    fi


    if $use_edk2; then
        CMD+=(-bios "$RUN_EDK2_DIR/QEMU_EFI.fd")
    fi

    if $use_net_tap; then
        CMD+=(-device virtio-net-pci,netdev=net0,romfile=\'\',mac='$tapaddress' -netdev tap,fd=3,id=net0)
    else
        CMD+=(-device virtio-net-pci,netdev=net0,romfile=\'\' -netdev user,id=net0)
    fi

    CMD+=(
        -cpu host -M virt -enable-kvm -M gic-version=3,its=on
        -smp 2 -m 512M
        -nographic
        #-device virtio-9p-pci,fsdev=shr0,mount_tag=shr0
        #-fsdev local,security_model=none,path=/mnt/shr0,id=shr0
        -dtb qemu-gen.dtb
    )

    APPEND=(-append "${KPARAMS[*]}")
fi

if [ -n "CORIM_OUTPUT" ]; then
    # Try the default sample files
    [ -z "$CORIM_TEMPLATE" ] && CORIM_TEMPLATE=samples/corim-cca-realm.json
    [ -z "$COMID_TEMPLATE" ] && COMID_TEMPLATE=samples/comid-cca-realm.json

    tmp=$(mktemp -d)
    [ -d "$tmp" ] || exit 1
    trap "rm -r '$tmp'" EXIT
    COMID_OUTPUT="$tmp/comid.json"

    CORIM_PARAMS=(
        --endorsements-template "$COMID_TEMPLATE"
        --endorsements-output "$COMID_OUTPUT"
    )
fi

declare -a extra_args
$gen_token || extra_args+=(--no-token)
$verbose && extra_args+=(-v)

set -x
$REALM_TOKEN \
    -c "$CONFIGS_DIR/qemu-max-8.2.conf" -c "$CONFIGS_DIR/kvm.conf" \
    --output-dtb "$OUTPUT_DTB" \
    -k "$KERNEL" \
    -i "$INITRD" \
    -f "$EDK2" \
    ${extra_args[@]} \
    "${CORIM_PARAMS[@]}" \
    $vmm "${CMD[@]}" "${APPEND[@]}"
{ set +x; } 2>/dev/null

if [ -n "$CORIM_OUTPUT" ]; then
    cocli comid create --template "$COMID_OUTPUT" -o "$tmp"
    cocli corim create --template "$CORIM_TEMPLATE" --comid "$tmp/comid.cbor" \
        --output "$CORIM_OUTPUT"
fi

cat << EOF > "$OUTPUT_SCRIPT"
#!/bin/bash

if $use_direct_kernel; then
    run_disk="${RUN_ROOTFS}"
else 
    run_disk="${RUN_DISK}"
fi

# Rough platform detection
if [ -n "\$(dmesg | grep FVP)" ]; then
	GUEST_TTY=/dev/ttyAMA1
    # FVP 9p doesn't support whatever QEMU is trying to do the the rootfs. F_SETLK maybe?
    cp "\$run_disk" /tmp/guest_disk
else
	GUEST_TTY=/dev/hvc1
    ln -fs "\$run_disk" /tmp/guest_disk
fi

if $use_net_tap; then
    tapindex=\$(cat /sys/class/net/macvtap0/ifindex)
    tapaddress=\$(cat /sys/class/net/macvtap0/address)
    tapdevice="/dev/tap\$tapindex"
fi

set -x
EOF

if [ $vmm = kvmtool ]; then
    vmm_cmd="lkvm run"
elif [ "$vmm" = "cloud-hv" ]; then
    vmm_cmd="${CLOUDHV_BIN:-cloud-hypervisor}"
else
    vmm_cmd=qemu-system-aarch64
fi

if $separate_console; then
    REDIRECT='>$GUEST_TTY <$GUEST_TTY &'
else
    REDIRECT=
fi

echo $vmm_cmd "${CMD[@]}" \
    $(printf "'%s' " "${APPEND[@]}")  \
    $($use_net_tap && printf '3<>$tapdevice') \
    $REDIRECT \
    >> "$OUTPUT_SCRIPT"

chmod +x "$OUTPUT_SCRIPT"
