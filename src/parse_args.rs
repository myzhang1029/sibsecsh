use std::env;

/// Parse command line arguments, the first reture value is the aargument to
/// -c if any, and the second argument is the other arguments
pub fn parse_args() -> (Option<String>, Vec<String>) {
    let all_args: Vec<String> = env::args().map(|x| x.to_string()).collect();
    info!("Program arguments: {:?}", all_args);
    for (i, argument) in env::args().enumerate() {
        if argument == "-c" {
            let mut other: Vec<String> = all_args[1..i].to_vec();
            let mut at_the_back = all_args[i + 2..all_args.len()].to_vec();
            other.append(&mut at_the_back);
            return (Some(all_args[i + 1].clone()), other);
        }
    }
    (None, all_args[1..all_args.len()].to_vec())
}
