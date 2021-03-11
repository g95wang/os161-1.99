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
#include <vm.h>
#include <vfs.h>
#include <kern/fcntl.h>
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

int sys_execv(userptr_t program, userptr_t args)
{
  struct addrspace *as;
  struct vnode *v;
  vaddr_t entrypoint, stackptr;
  int result;

  unsigned argc = 0;
  char **argv;

  int err, dummy;

  /* copy program name */
  char *progname = kmalloc(128 * sizeof(char));
  if (progname == NULL)
  {
    return ENOMEM;
  }
  err = copyinstr(program, progname, 128, (size_t *)&dummy);
  if (err)
  {
    return err;
  }

  /* copy argv */
  argv = kmalloc(128 * sizeof(char *));
  if (argv == NULL)
  {
    return ENOMEM;
  }

  for (int i = 0;; i++)
  {
    argv[i] = kmalloc(128 * sizeof(char));
    if (argv[i] == NULL)
    {
      return ENOMEM;
    }
    char *ptr;
    err = copyin((userptr_t)(args + 4 * i), (void *)&ptr, 4);
    if (err)
    {
      return err;
    }
    if (ptr == NULL)
    {
      break;
    }
    argc++;
    err = copyinstr((userptr_t)ptr, argv[i], 128, (size_t *)&dummy);
    if (err)
    {
      return err;
    }
  }

  // Copied from runprogram
  /* Open the file. */
  result = vfs_open(progname, O_RDONLY, 0, &v);
  if (result)
  {
    return result;
  }

  /* Create a new address space. */
  as = as_create();
  if (as == NULL)
  {
    vfs_close(v);
    return ENOMEM;
  }

  /* Switch to it and activate it. */
  struct addrspace *old_as = curproc_setas(as);
  as_activate();

  /* Load the executable. */
  result = load_elf(v, &entrypoint);
  if (result)
  {
    /* p_addrspace will go away when curproc is destroyed */
    vfs_close(v);
    return result;
  }

  /* Done with the file now. */
  vfs_close(v);

  /* Define the user stack in the address space */
  result = as_define_stack(as, &stackptr);
  if (result)
  {
    /* p_addrspace will go away when curproc is destroyed */
    return result;
  }
  // End of Copied from runprogram

  struct array *stackptrs = array_create();
  userptr_t stacktop = (userptr_t)stackptr;

  // argv
  for (unsigned i = 0; i < argc; i++)
  {
    char *arg = argv[i];
    stacktop -= strlen(arg) + 1;
    err = array_add(stackptrs, (void *)stacktop, (unsigned *)&dummy);
    if (err)
    {
      return err;
    }
    err = copyoutstr(arg, stacktop, 128, (size_t *)&dummy);
    if (err)
    {
      return err;
    }
  }

  // pointers
  stacktop = (userptr_t)(ROUNDUP((unsigned)stacktop, 8) - 16);
  stacktop -= 8 * ROUNDUP(argc + 2, 2);
  userptr_t top = stacktop;
  for (unsigned i = 0; i < argc; i++)
  {
    userptr_t ptr = array_get(stackptrs, i);
    err = copyout((void *)&ptr, (userptr_t)stacktop, 4);
    if (err)
    {
      return err;
    }
    stacktop += 4;
  }
  void *ptr = NULL;
  err = copyout((void *)&ptr, (userptr_t)stacktop, 4);
  if (err)
  {
    return err;
  }

  as_destroy(old_as);
  kfree(progname);
  for (unsigned i = 0; i <= argc; i++)
  {
    kfree(argv[i]);
  }
  kfree(argv);

  /* Warp to user mode. */
  enter_new_process(argc, top,
                    (vaddr_t)top, entrypoint);

  /* enter_new_process does not return. */
  panic("enter_new_process returned\n");
  return EINVAL;
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
  if (p->parent == NULL || p->parent->status == Zombie)
  {
    proc_destroy(p);
  }
  else
  {
    lock_acquire(p->p_Lock);
    p->status = Zombie;
    p->exitcode = exitcode;
    cv_broadcast(p->p_cv, p->parent->p_Lock);
    lock_release(p->p_Lock);
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
