package applyd

import (
    "fmt"
    "log"
    "os/exec"
)

func Execute(cmd *exec.Cmd) (output []byte, err error) {
    output, err = cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed %s", cmd)
        log.Printf("Output: %s", output)

        return nil, fmt.Errorf("Error running %s: %s", cmd, err)
    }
    return output, nil
}
