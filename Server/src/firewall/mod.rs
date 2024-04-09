pub mod firewall{
    use std::process::{Command, Output};
    use std::time::Duration;
    use crate::ip::ip::IP;
    use crate::smurf_scanner::smurf_scanner::ATTACK_NAME;

    ///The function blocks a specific ip with
    /// firewall inbound rule.
    /// Input: an IP variable- the ip to block.
    /// Output: The result of the blocking.
    pub fn block_ip(ip_attacker: IP) -> Result<Output, String> {
        let mut name_arg = "name=";
        let mut rule_name = "IDS-".to_string() + ip_attacker.get_ip().as_mut_str();
        let mut binding = Command::new("netsh");
        let mut command = binding
            .arg("advfirewall")
            .arg("firewall")
            .arg("add")
            .arg("rule")
            .arg(name_arg.to_owned() + rule_name.as_mut_str())
            .arg("dir=out")
            .arg("action=block")
            .arg(format!("remoteip={}", ip_attacker.get_ip().as_mut_str()));

        if is_rule_exists(rule_name){
            return Err("This rule is already exists!".to_string());
        }
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
    fn block_icmp() -> Result<Output, String>{
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
    fn allow_icmp() -> Result<Output, String>{
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
    fn run_command(mut command: &mut Command) -> Result<Output, String>{
        let result = command.output();

        return match result {
            Ok(output) => {
                if output.status.success() {
                    return Ok(output);
                }
                Err("No success running firewall command! It might be related to running without Administrator privilege".to_string())
            }
            Err(e) => {
                Err(e.to_string())
            }
        }
    }

    ///The function checks if a specific rule is
    /// already exists or not.
    /// Input: a String variable- the name of the rule.
    /// Output: a bool value- the answer.
    fn is_rule_exists(rule_name: String) -> bool{
        //Making the command
        let mut binding = Command::new("netsh");
        let command = binding
            .args(&["advfirewall", "firewall", "show", "rule", "name=all"]);

        //Checking if the command can be executed
        let result_command = run_command(command);
        return match result_command {
            Ok(output) => {
                //Getting&Checking the command's output
                let string_output = String::from_utf8_lossy(&output.stdout).clone();
                string_output.clone().contains(rule_name.as_str())
            }
            Err(_) => { false }
        };
    }
}