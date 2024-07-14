import {add} from './1-main'
import {detect_toolchain_msvc} from "./toolchain/detect_toolchain_msvc";

print(`1 + 1 = ${add(1, 1)}`)
detect_toolchain_msvc();
print('---')