#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""
    CLI for submitting SLURM jobs on DeepGreen
"""

import argparse
import os


def submitter_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Constructs a SLURM script for use on DeepGreen.",
    )
    parser.add_argument("--job", help="Job you wish to run. ex. python myscript.py.")
    parser.add_argument(
        "--days", default=0, type=int, help="Number of days to use in job time limit."
    )
    parser.add_argument(
        "--hours", default=0, type=int, help="Number of hours to use in job time limit."
    )
    parser.add_argument(
        "--minutes",
        default=0,
        type=int,
        help="Number of seconds to use in job time limit.",
    )
    parser.add_argument(
        "--seconds",
        default=0,
        type=int,
        help="Number of seconds to use in job time limit.",
    )
    parser.add_argument(
        "--job_name", default="job", help="Name of job. Output file is name_id.out"
    )
    parser.add_argument(
        "--conda_env",
        default="uvm_ids",
        help="Conda environment to activate before running job.",
    )
    parser.add_argument(
        "--email",
        default="",
        help="Optional address to send email reports. "
        "If set mail_type defaults to ALL. "
        "This may be overwritten by using the mail type flags.",
    )
    parser.add_argument(
        "--mail_begin",
        action="store_true",
        help="Removes ALL from mail-type and adds BEGIN. Has no effect if email is not set.",
    )
    parser.add_argument(
        "--mail_end",
        action="store_true",
        help="Removes ALL from mail-type and adds END. Has no effect if email is not set.",
    )
    parser.add_argument(
        "--mail_fail",
        action="store_true",
        help="Removes ALL from mail-type and adds FAIL. Has no effect if email is not set.",
    )
    parser.add_argument(
        "--nodes",
        default=1,
        type=int,
        help="Number of physical compute nodes to request.",
    )
    parser.add_argument(
        "--ntasks", default=1, type=int, help="Number of processors to request."
    )
    parser.add_argument(
        "--mem",
        default=16,
        type=int,
        help="Amount of memory to request. Unit is set by mem_unit (default G).",
    )
    parser.add_argument(
        "--mem_unit",
        default="G",
        choices=["K", "M", "G", "T"],
        help="Unit for mem arg. K=kilobytes, M=megabytes, G=gigabytes, T=terabytes.",
    )
    parser.add_argument(
        "--gpus", default=1, type=int, help="Number of GPUs to request."
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Prints script to console instead of submitting.",
    )

    return parser


def main(
    job,
    days=0,
    hours=0,
    minutes=0,
    seconds=0,
    job_name="job",
    conda_env="uvm_ids",
    email="",
    mail_begin=False,
    mail_end=False,
    mail_fail=False,
    nodes=1,
    ntasks=1,
    mem=16,
    mem_unit="G",
    gpus=1,
    preview=False,
):
    # at least one time param is required
    submit_script = "#!/bin/bash\n#SBATCH --partition=gpu\n"
    submit_script += f"#SBATCH --nodes={nodes}\n"
    #submit_script += f"#SBATCH --ntasks={ntasks}\n"
    submit_script += f"#SBATCH --gres=gpu:{gpus}\n"
    submit_script += (
        f"#SBATCH --time={days:02d}-{hours:02d}:{minutes:02d}:{seconds:02d}\n"
    )
    submit_script += f"#SBATCH --mem={mem}{mem_unit}\n"
    if email:
        submit_script += f"#SBATCH --mail-user={email}\n"
        mail_types = []
        if mail_begin:
            mail_types.append("BEGIN")
        if mail_end:
            mail_types.append("END")
        if mail_fail:
            mail_types.append("FAIL")
        if not mail_types:
            mail_types.append("ALL")
        mail_types = ",".join(mail_types)
        submit_script += f"#SBATCH --mail-type={mail_types}\n"
    submit_script += f"#SBATCH --job-name={job_name}\n"
    submit_script += "# %x=job-name %j=jobid\n#SBATCH --output=%x_%j.out\n"
    submit_script += "source activate /home/***/uvm_env\n"
    submit_script += 'cd "${SLURM_SUBMIT_DIR}" || exit\n'
#    if conda_env:
#        submit_script += f"source activate {conda_env}\n"
    submit_script += f"{job.strip()}\n"
    if preview:
        print(submit_script)
    else:
        with open("submit.sbatch", "w") as f:
            f.write(submit_script)
        os.system("sbatch submit.sbatch")


if __name__ == "__main__":
    parser = submitter_args()
    main(**vars(parser.parse_args()))
