#include "printer.hh"
#include "banner.hh"

void print_f7ly() {
    // 第1行
    printfRed("%s",F_L1);
    printfRed("%s",S7_L1);
    printfRed("%s",L_L1);
    printfRed("%s",Y_L1);
    printfRed("\n");

    // 第2行
    printfMagenta("%s",F_L2);
    printfMagenta("%s",S7_L2);
    printfMagenta("%s",L_L2);
    printfMagenta("%s",Y_L2);
    printfMagenta("\n");

    // 第3行
    printfCyan("%s",F_L3);
    printfCyan("%s",S7_L3);
    printfCyan("%s",L_L3);
    printfCyan("%s",Y_L3);
    printfCyan("\n");

    // 第4行
    printfYellow("%s",F_L4);
    printfYellow("%s",S7_L4);
    printfYellow("%s",L_L4);
    printfYellow("%s",Y_L4);
    printfYellow("\n");

    // 第5行
    printfGreen("%s",F_L5);
    printfGreen("%s",S7_L5);
    printfGreen("%s",L_L5);
    printfGreen("%s",Y_L5);
    printfGreen("\n");

    // 第6行
    printfWhite("%s",F_L6);
    printfWhite("%s",S7_L6);
    printfWhite("%s",L_L6);
    printfWhite("%s",Y_L6);
    printfWhite("\n");
}
