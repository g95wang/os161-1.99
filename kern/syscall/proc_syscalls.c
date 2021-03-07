#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include <mips/trapframe.h>
#include <array.h>
#include <spl.h>
#include "opt-A2.h"

#if OPT_A2

int sys_fork(struct trapframe *tf, pid_t *retval)
{
  int err;
  unsigned ret;
  struct proc *parent = curproc;

  struct proc *child = proc_create_runprogram("child_proc");
  if (child == NULL)
  {
    return ENOMEM;
  }

  lock_acquire(parent->p_Lock);

  err = array_add(parent->children, (void *)child, &ret);
  if (err)
  {
    proc_destroy(child);
    lock_release(parent->p_Lock);
    return err;
  }
  child->parent = parent;

  spinlock_acquire(&parent->p_lock);
  err = as_copy(parent->p_addrspace, &child->p_addrspace);
  spinlock_release(&parent->p_lock);
  if (err)
  {
    proc_destroy(child);
    lock_release(parent->p_Lock);
    return err;
  }

  struct trapframe *new_tf = kmalloc(sizeof(struct trapframe));
  if (new_tf == NULL)
  {
    proc_destroy(child);
    lock_release(parent->p_Lock);
    return ENOMEM;
  }
  *new_tf = *tf;

  lock_release(parent->p_Lock);

  thread_fork("child_thread", child, enter_forked_process, (void *)new_tf, 0);

  *retval = child->pid;

  return 0;
}

#endif

/* this implementation of sys__exit does not do anything with the exit code */
/* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode)
{
  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
  (void)exitcode;

  DEBUG(DB_SYSCALL, "Syscall: _exit(%d)\n", exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);
#if OPT_A2
  // // destroy Zombie children
  // for (unsigned i = 0; i < array_num(p->children); i++)
  // {
  //   struct proc *child = (struct proc *)array_get(p->children, i);
  //   if (child != NULL && child->status != Alive)
  //   {
  //     proc_destroy(child);
  //     array_set(p->children, i, NULL);
  //   }
  // }

  if (p->parent == NULL || p->parent->status == Zombie)
  {
    proc_destroy(p);
  }
  else
  {
    p->status = Zombie;
    p->exitcode = exitcode;
    cv_broadcast(p->p_cv, p->parent->p_Lock);
  }
#else
  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
#endif

  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}

/* stub handler for getpid() system call                */
int sys_getpid(pid_t *retval)
{
#if OPT_A2
  *retval = curproc->pid;
  return 0;
#else
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
  *retval = 1;
  return (0);
#endif
}

/* stub handler for waitpid() system call                */

int sys_waitpid(pid_t pid,
                userptr_t status,
                int options,
                pid_t *retval)
{
  int exitstatus;
  int result;

  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.   
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.

     Fix this!
  */

  if (options != 0)
  {
    return (EINVAL);
  }
#if OPT_A2
  DEBUG(DB_SYSCALL, "Syscall: %d waitpid(%d)\n", curproc->pid, pid);
  bool hasChild = false;
  struct proc *parent = curproc;
  lock_acquire(parent->p_Lock);
  for (unsigned i = 0; i < array_num(parent->children); i++)
  {
    struct proc *child = (struct proc *)array_get(parent->children, i);
    if (pid == child->pid)
    {
      hasChild = true;
      while (child->status == Alive)
      {
        cv_wait(child->p_cv, parent->p_Lock);
      }
      exitstatus = _MKWAIT_EXIT(child->exitcode);
      break;
    }
  }
  lock_release(parent->p_Lock);

  if (!hasChild)
  {
    *retval = -1;
    return ESRCH;
  }
#else
  /* for now, just pretend the exitstatus is 0 */
  exitstatus = 0;
#endif
  result = copyout((void *)&exitstatus, status, sizeof(int));
  if (result)
  {
    return (result);
  }
  *retval = pid;
  return (0);
}
