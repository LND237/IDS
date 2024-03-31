pub mod firewall{
    use std::process::Command;
    use std::time::Duration;
    use crate::ip::ip::IP;
    use crate::smurf_scanner::smurf_scanner::ATTACK_NAME;

    ///The function blocks a specific ip with
    /// firewall inbound rule.
    /// Input: an IP variable- the ip to block.
    /// Output: The result of the blocking.
    pub fn block_ip(ip_attacker: IP) -> Result<(), String> {
        let mut rule_name = "IDS - ".to_string() + ip_attacker.get_ip().as_mut_str();
        let mut binding = Command::new("netsh");
        let mut command = binding
            .arg("advfirewall")
            .arg("firewall")
            .arg("add")
            .arg("rule")
            .arg("name=\"".to_owned() + rule_name.as_mut_str() + "\"")
            .arg("dir=in")
            .arg("action=block")
            .arg(format!("remoteip={}", ip_attacker.get_ip().as_mut_str()));

        return run_command(&mut command);
    }

    ///The function blocks the icmp protocol for a limited time.
    /// Input: an i32 variable- the amount of time
    /// to block(in seconds).
    /// Output: None.
    pub async fn block_icmp_limited_time(amount_time_blocking: i32){
        let _ = block_icmp();

        tokio::time::sleep(Duration::from_secs(amount_time_blocking as u64)).await;

        let _ = allow_icmp();
    }

    ///The function blocks the icmp protocol.
    /// Input: None.
    /// Output: The result of the blocking.
    fn block_icmp() -> Result<(), String>{
        let mut rule_name = "IDS-".to_string() + ATTACK_NAME;
        let mut binding = Command::new("netsh");
        let command = binding
            .arg("advfirewall")
            .arg("firewall")
            .arg("add")
            .arg("rule")
            .arg("name=\"".to_owned() + rule_name.as_mut_str() + "\"")
            .arg("protocol=icmpv4")
            .arg("dir=out")
            .arg("action=block");
        return run_command(command);
    }

    ///The function allows the icmp protocol. It
    /// is bases on the blocking icmp rule.
    /// Input: None.
    /// Output: The result of the allowing.
    fn allow_icmp() -> Result<(), String>{
        let mut rule_name = "IDS-".to_string() + ATTACK_NAME;
        let mut binding = Command::new("netsh");
        let mut command = binding
            .arg("advfirewall")
            .arg("firewall")
            .arg("delete")
            .arg("rule")
            .arg("name=\"".to_owned() + rule_name.as_mut_str() + "\"");

        return run_command(&mut command);
    }

    ///The function runs a command.
    /// Input: a mutable reference of Command- the command
    /// to execute.
    /// Output: The result of the command.
    fn run_command(mut command: &mut Command) -> Result<(), String>{
        let result = command.output();

        return match result {
            Ok(output) => {
                if output.status.success() {
                    return Ok(());
                }
                Err("No success running firewall command".to_string())
            }
            Err(e) => {
                Err(e.to_string())
            }
        }
    }
}