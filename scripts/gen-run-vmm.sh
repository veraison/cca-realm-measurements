#!/bin/bash
#
# This script can perform two operations:
#
# * Launch a Realm VM using kvmtool, QEMU or cloud-hypervisor. A DTB is
#   generated into the current directory. This is the default mode.
#
# * Generate reference values corresponding to a given VM invocation, that can
#   be provisioned into a verifier. For this, add --corim-output to the
#   arguments.

set -eu

use_virtconsole=true
use_edk2=false
use_event_log=false
use_direct_kernel=true
use_initrd=true
use_rme=true
use_net_tap=false
host_fvp=false
verbose=false
separate_console=false
vmm=qemu
share=false
vsock=false

gen_dtb=true
gen_measurements=false

: ${CFG:=gen-run-vmm.cfg}

# Try to find a config file containing KERNEL and INITRD
for cfg in $CFG /usr/share/cca-realm-measurements/gen-run-vmm.cfg; do
    if [ -f "$cfg" ]; then
        source "$cfg"
        break;
    fi
done

# Paths for the generator
: ${KERNEL:=}
: ${INITRD:=}
: ${EDK2_DIR:=}

: ${OUTPUT_SCRIPT_DIR:=.}
: ${OUTPUT_DTB_DIR:=.}
: ${OUTPUT_DTB:=}

: ${RVSTORE_DIR:=}
: ${CONFIGS_DIR:=/usr/share/cca-realm-measurements/configs}
: ${REALM_MEASUREMENTS:=realm-measurements}

# Paths for the generated run script
: ${RUN_KERNEL:=$KERNEL}
: ${RUN_INITRD:=$INITRD}
: ${RUN_EDK2_DIR:=$EDK2_DIR}
# A disk containing two partitions: the first is an EFI partition with the
# kernel and bootloader, and the second is the userspace (e.g. buildroot).
: ${RUN_DISK:=guest_disk}

MEM_SIZE=1G

: ${SHARED_DIR:=/mnt/}
: ${VSOCK_ID:=3}

COMID_TEMPLATE=
CORIM_TEMPLATE=
CORIM_OUTPUT=

INPUT_RVSTORE="$RVSTORE_DIR/rv.json"

TEMP=$(getopt -o 'hvT' --long 'help,edk2,eventlog,fvp,disk-boot,disk,gen-measurements,serial,no-gen-dtb,no-rme,kvmtool,cloudhv,tap,verbose,comid-template:,corim-template:,corim-output:,extcon,share::,vsock::' -n 'gen-run-vmm' -- "$@")
if [ $? -ne 0 ]; then
    exit 1
fi

serial_console=ttyAMA0
earlycon=pl011
earlycon_addr=0x09000000
# FIXME: increase this if you ask for more than 255GB of RAM
ipa_bits=41

eval set -- "$TEMP"
unset TEMP
while true; do
    case "$1" in
    '--edk2')
        use_edk2=true
        ;;
    '--disk-boot')
        use_direct_kernel=false
        use_initrd=false
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
    '--no-gen-dtb')
        gen_dtb=false
        ;;
    '--kvmtool')
        vmm=kvmtool
        serial_console=ttyS0
        earlycon=uart,mmio
        earlycon_addr=0x01000000
        # FIXME: increase this if you ask for more than 2GB of RAM
        ipa_bits=33
        ;;
    '--cloudhv')
        vmm=cloud-hv
        use_net_tap=true
        ipa_bits=48
        ;;
    '--eventlog')
        use_event_log=true
        ;;
    '--fvp')
        host_fvp=true
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
        gen_measurements=true
        shift
        ;;
    '--gen-measurements')
        gen_measurements=true
        ;;
    '--extcon')
        separate_console=true
        ;;
    '--share')
        share=true
        if [ -n "$2" ]; then
            SHARED_DIR="$2"
        fi
        shift
        ;;
    '-v'|'--verbose')
        verbose=true
        ;;
    '--vsock')
        vsock=true
        if [ -n "$2" ]; then
            VSOCK_ID="$2"
        fi
        shift
        ;;
    '-h'|'--help')
        cat << EOF
Usage: $0
Launch a guest in a realm. Generate the DTB file corresponding to the VM
in the current directoy. The default VMM is QEMU.

  --cloudhv             Use cloud-hypervisor as VMM
  --disk-boot           Boot from disk instead of direct kernel boot
  --disk                Use disk as userspace instead of initrd
  --edk2                Use ekd2 firmware
  --eventlog            Create an event log for the Realm Initial Measurement
  --fvp                 Host platform is FVP (default QEMU)
  --no-gen-dtb          Don't pass a generated DTB to the VMM
  --extcon              Use a separate in+out console for the guest
  --kvmtool             Use kvmtool as VMM
  --no-rme              Disable RME
  --serial              Use serial instead of virtconsole
  --share [dir]         Share directory with the guest (default '${SHARED_DIR}')
  --tap                 Use tap networking instead of user
  --vsock [id]          Instantiate a vsock device
  -v --verbose          Be more verbose

In "measurements" mode, generate the measurements instead of running the VM:

  --gen-measurements    Generate and print measurements
  --comid-template <file.json>
  --corim-template <file.json>
  --corim-output <file.cbor>  Generate CoMID file containing reference values
EOF
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

VIRTIOFSD_SOCK=/tmp/virtiofsd.sock
launch_virtiofsd () {
    if [ -e "$VIRTIOFSD_SOCK" ]; then
        echo "error: virtiofsd is already running"
        exit 1
    fi
    virtiofsd --shared-dir "$SHARED_DIR" --socket-path "$VIRTIOFSD_SOCK" &
}

declare -a CMD
declare -a KPARAMS

if $use_virtconsole; then
    KPARAMS+=(console=hvc0)
else
    # earlycon needs to be accessed via physical address, which unfortunately
    # depends on the IPA size :(
    if $use_rme; then
        earlycon_addr=$(printf "0x%x" $((earlycon_addr | (1 << (ipa_bits - 1)))))
    fi

    KPARAMS+=(earlycon=$earlycon,$earlycon_addr console=$serial_console)
fi

if ! $use_initrd; then
    KPARAMS+=(root=/dev/vda2)
fi

if ! $gen_measurements; then
    # Rough platform detection
    if [ -n "$(dmesg | grep FVP)" ]; then
        host_fvp=true
    fi

    if $host_fvp; then
        GUEST_TTY=/dev/ttyAMA1
        # FVP 9p implementation is rather restrictive, and doesn't support
        # several operations, such as locking by QEMU. It's also broken for
        # edk2. Copy the disk to a safer location.
        if ! $use_initrd; then
            cp -v $RUN_DISK /tmp/guest_disk
            RUN_DISK=/tmp/guest_disk
        fi
    else
        # QEMU machine provides virtio-console
        GUEST_TTY=/dev/hvc1
    fi

    if $use_net_tap; then
        tapindex=$(cat /sys/class/net/macvtap0/ifindex)
        tapaddress=$(cat /sys/class/net/macvtap0/address)
        if [ "$vmm" != "kvmtool" ]; then
            exec 3<>/dev/tap$tapindex
        fi
    fi
else
    # In "measurement" mode, users can request to generate a DTB by setting
    # OUTPUT_DTB.
    if [ -z "$OUTPUT_DTB" ]; then
        gen_dtb=false
    fi

    tapindex=
    tapaddress=
fi

# printf "%64s" "I'm a teapot" | base64 -w0
RPV=ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEknbSBhIHRlYXBvdA==

if [ "$vmm" = "kvmtool" ]; then
    : ${OUTPUT_DTB:="$OUTPUT_DTB_DIR/kvmtool-gen.dtb"}
    EDK2="$EDK2_DIR/Build/ArmVirtKvmtool-AARCH64/DEBUG_GCC5/FV/KVMTOOL_EFI.fd"

    if $use_virtconsole; then
        CMD+=(--console virtio)
    else
        CMD+=(--console serial)
    fi

    if $use_net_tap; then
        CMD+=(-n mode=tap,tapif=/dev/tap$tapindex,guest_mac=$tapaddress)
    fi

    if $use_rme; then
        CMD+=(--realm --restricted_mem --sve-max-vl=512)
    fi

    if $use_edk2; then
        CMD+=(-f "${RUN_EDK2_DIR}/KVMTOOL_EFI.fd")
    fi

    if $use_direct_kernel; then
        CMD+=(-k "${RUN_KERNEL}")
    fi

    CMD+=(
        -c 2 -m $MEM_SIZE
        --virtio-transport pci
        --irqchip=gicv3-its
        --pmu
        --network mode=user
        #--9p /mnt/shr0,shr0
        --debug
    )
    if $gen_dtb; then
        CMD+=(--dtb kvmtool-gen.dtb)
    fi
    if $use_initrd; then
        CMD+=(-i "$RUN_INITRD")
    else
        CMD+=(-d "$RUN_DISK")
    fi
    if $use_event_log; then
        CMD+=(--measurement-log)
    fi

    if [ -n "${KPARAMS[*]}" ]; then
        APPEND=(-p "${KPARAMS[*]}")
    fi
elif [ "$vmm" = "cloud-hv" ]; then
    : ${OUTPUT_DTB:="$OUTPUT_DTB_DIR/cloudhv-gen.dtb"}
    EDK2="$EDK2_DIR/Build/ArmVirtCloudHv-AARCH64/DEBUG_GCC5/FV/QEMU_EFI.fd"

    if $use_rme; then
        CMD+=(--platform "arm_rme=on,measurement_algo=sha512,personalization_value=$RPV")
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
            CMD+=(--disk path="$RUN_DISK")
        fi
    else
        CMD+=(--disk path="$RUN_DISK")
    fi


    if $use_edk2; then
        CMD+=(-bios "$RUN_EDK2_DIR/QEMU_EFI.fd")
    fi

    CMD+=(
        --cpus boot=2
        --memory size=$MEM_SIZE
        --net fd=3,mac=$tapaddress
        -v
    )
    if $gen_dtb; then
        CMD+=(--dtb cloudhv-gen.dtb)
    fi

    APPEND=(--cmdline "${KPARAMS[*]}")
else # QEMU
    : ${OUTPUT_DTB:="$OUTPUT_DTB_DIR/qemu-gen.dtb"}
    EDK2="$EDK2_DIR/Build/ArmVirtQemu-AARCH64/DEBUG_GCC5/FV/QEMU_EFI.fd"

    if $use_event_log; then
        measurement_log=on
    else
        measurement_log=off
    fi

    if $use_rme; then
        CMD+=(-M confidential-guest-support=rme0 -object rme-guest,id=rme0,measurement-algorithm=sha512,personalization-value=$RPV,measurement-log=$measurement_log)
    fi

    if $use_virtconsole; then
        CMD+=(-nodefaults
              -chardev stdio,mux=on,id=chr0,signal=off
              -serial chardev:chr0
              -device virtio-serial-pci
              -device virtconsole,chardev=chr0
              -mon chardev=chr0,mode=readline)
    fi

    if $use_edk2; then
        CMD+=(-bios "$RUN_EDK2_DIR/QEMU_EFI.fd")
    fi

    if $use_net_tap; then
        CMD+=(-device virtio-net-pci,netdev=net0,romfile='',mac=$tapaddress -netdev tap,fd=3,id=net0)
    else
        CMD+=(-device virtio-net-pci,netdev=net0,romfile='' -netdev user,id=net0)
    fi

    CMD+=(
        -cpu host -M virt -enable-kvm -M gic-version=3,its=on
        -smp 2 -m $MEM_SIZE
        -nographic
        #-device virtio-9p-pci,fsdev=shr0,mount_tag=shr0
        #-fsdev local,security_model=none,path=/mnt/shr0,id=shr0
    )

    if $gen_dtb; then
        CMD+=(-dtb qemu-gen.dtb)
    fi

    if $use_direct_kernel; then
        CMD+=(-kernel "$RUN_KERNEL")
        if $use_initrd; then
            CMD+=(-initrd "$RUN_INITRD")
        else
            CMD+=(-device virtio-blk-pci,drive=rootfs0)
            CMD+=(-drive format=raw,if=none,file=$RUN_DISK,id=rootfs0)
        fi

        APPEND=(-append "${KPARAMS[*]}")
    else
        CMD+=(-device virtio-blk-pci,drive=rootfs0)
        CMD+=(-drive format=raw,if=none,file=$RUN_DISK,id=rootfs0)
    fi

    if $vsock; then
        CMD+=(
            -device vhost-vsock-pci,guest-cid="$VSOCK_ID"
        )
    fi

    if $share; then
        launch_virtiofsd
        CMD+=(
            -chardev socket,id=vfs0,path="$VIRTIOFSD_SOCK"
            -device vhost-user-fs-pci,queue-size=1024,chardev=vfs0,tag=vfs0
        )
    fi
fi

if [ -n "$CORIM_OUTPUT" ]; then
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
if $gen_measurements; then
    extra_args+=(--print-b64)
else
    extra_args+=(--no-measurements)
fi
if $gen_dtb; then
    extra_args+=(--output-dtb "$OUTPUT_DTB")
fi
$verbose && extra_args+=(-v)

if $host_fvp; then
    platform_config=fvp.conf
else
    platform_config=qemu-max-8.2.conf
fi

if $gen_dtb || $gen_measurements; then
    # When running the VM, the following only generates a DTB
    set -x
    $REALM_MEASUREMENTS \
        -c "$CONFIGS_DIR/$platform_config" -c "$CONFIGS_DIR/kvm.conf" \
        -k "$KERNEL" \
        -i "$INITRD" \
        -f "$EDK2" \
        ${extra_args[@]} \
        "${CORIM_PARAMS[@]}" \
        $vmm "${CMD[@]}" "${APPEND[@]}"
    { set +x; } 2>/dev/null
fi

if [ -n "$CORIM_OUTPUT" ]; then
    cocli comid create --template "$COMID_OUTPUT" -o "$tmp"
    cocli corim create --template "$CORIM_TEMPLATE" --comid "$tmp/comid.cbor" \
        --output "$CORIM_OUTPUT"

    exit
elif $gen_measurements; then
    exit
fi

#
# Now run the VM
#
if [ $vmm = kvmtool ]; then
    vmm_cmd="lkvm run"
elif [ "$vmm" = "cloud-hv" ]; then
    vmm_cmd="${CLOUDHV_BIN:-cloud-hypervisor}"
else
    vmm_cmd=qemu-system-aarch64
fi

if $separate_console; then
    exec >$GUEST_TTY <$GUEST_TTY
fi

set -x
$vmm_cmd "${CMD[@]}" "${APPEND[@]}"
