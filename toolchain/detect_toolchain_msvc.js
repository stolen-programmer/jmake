import {which} from "native"
import {Toolchain} from './detect'

class MSVCToolchain extends Toolchain {
    constructor(vc_install_path) {
        super();
    }

    compile(src) {
        super.compile(src);
    }
}

export function detect_toolchain_msvc() {
    try {
        // let cl = which("where.exe")
    } catch (e) {
        print(e)
    }

    print(cl)
    return new MSVCToolchain();
}
