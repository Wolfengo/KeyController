#define _GNU_SOURCE
#include <wayland-client.h>
#include "capture-protocols/imagecopy.h"
#include "capture-protocols/imagesource.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
static struct wl_display *display;
static struct wl_output *output;
static struct wl_shm *shm;
static struct ext_output_image_capture_source_manager_v1 *sources;
static struct ext_image_copy_capture_manager_v1 *manager;
static uint32_t width,height,format=UINT32_MAX;
static int constraints=0,finished=0,failed=0;
static void geometry(void*d,struct wl_output*o,int32_t x,int32_t y,int32_t a,int32_t b,int32_t sub,const char*m,const char*n,int32_t t){}
static void mode(void*d,struct wl_output*o,uint32_t f,int32_t w,int32_t h,int32_t refresh){}
static const struct wl_output_listener out_listener={.geometry=geometry,.mode=mode};
static void global(void*d,struct wl_registry*r,uint32_t name,const char*iface,uint32_t version){
 if(!strcmp(iface,"wl_shm"))shm=wl_registry_bind(r,name,&wl_shm_interface,1);
 else if(!strcmp(iface,"wl_output")&&!output){output=wl_registry_bind(r,name,&wl_output_interface,1);wl_output_add_listener(output,&out_listener,NULL);}
 else if(!strcmp(iface,"ext_output_image_capture_source_manager_v1"))sources=wl_registry_bind(r,name,&ext_output_image_capture_source_manager_v1_interface,1);
 else if(!strcmp(iface,"ext_image_copy_capture_manager_v1"))manager=wl_registry_bind(r,name,&ext_image_copy_capture_manager_v1_interface,1);
}
static void global_remove(void*d,struct wl_registry*r,uint32_t n){}
static const struct wl_registry_listener registry_listener={global,global_remove};
static void size(void*d,struct ext_image_copy_capture_session_v1*s,uint32_t w,uint32_t h){width=w;height=h;}
static void shm_format(void*d,struct ext_image_copy_capture_session_v1*s,uint32_t f){if(f==WL_SHM_FORMAT_XRGB8888||f==WL_SHM_FORMAT_ARGB8888)format=f;}
static void dma_dev(void*d,struct ext_image_copy_capture_session_v1*s,struct wl_array*a){}
static void dma_format(void*d,struct ext_image_copy_capture_session_v1*s,uint32_t f,struct wl_array*a){}
static void done(void*d,struct ext_image_copy_capture_session_v1*s){constraints=1;}
static void stopped(void*d,struct ext_image_copy_capture_session_v1*s){failed=1;constraints=1;finished=1;}
static const struct ext_image_copy_capture_session_v1_listener session_listener={size,shm_format,dma_dev,dma_format,done,stopped};
static void transform(void*d,struct ext_image_copy_capture_frame_v1*f,uint32_t v){}
static void damage(void*d,struct ext_image_copy_capture_frame_v1*f,int32_t x,int32_t y,int32_t w,int32_t h){}
static void present(void*d,struct ext_image_copy_capture_frame_v1*f,uint32_t hi,uint32_t lo,uint32_t ns){}
static void ready(void*d,struct ext_image_copy_capture_frame_v1*f){finished=1;}
static void failure(void*d,struct ext_image_copy_capture_frame_v1*f,uint32_t reason){fprintf(stderr,"capture failed %u\n",reason);failed=1;finished=1;}
static const struct ext_image_copy_capture_frame_v1_listener frame_listener={transform,damage,present,ready,failure};
int main(void){
 alarm(5);
 // Refuse accidental execution against the real desktop.
 const char *runtime=getenv("XDG_RUNTIME_DIR");
 if(!runtime||strncmp(runtime,"/tmp/kc-",8)){fprintf(stderr,"isolated test runtime required\n");return 2;}
 display=wl_display_connect(NULL);if(!display)return 2;
 struct wl_registry *registry=wl_display_get_registry(display);wl_registry_add_listener(registry,&registry_listener,NULL);
 if(wl_display_roundtrip(display)<0||!output||!shm||!sources||!manager)return 3;
 struct ext_image_capture_source_v1 *source=ext_output_image_capture_source_manager_v1_create_source(sources,output);
 struct ext_image_copy_capture_session_v1 *session=ext_image_copy_capture_manager_v1_create_session(manager,source,0);
 ext_image_copy_capture_session_v1_add_listener(session,&session_listener,NULL);
 while(!constraints)if(wl_display_dispatch(display)<0)return 4;
 if(failed||!width||!height||width>4096||height>4096||format==UINT32_MAX)return 5;
 size_t bytes=(size_t)width*height*4;int fd=memfd_create("synthetic-imagecopy",MFD_CLOEXEC);if(fd<0||ftruncate(fd,bytes))return 6;
 uint8_t *pixels=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(pixels==MAP_FAILED)return 7;
 struct wl_shm_pool *pool=wl_shm_create_pool(shm,fd,bytes);struct wl_buffer *buffer=wl_shm_pool_create_buffer(pool,0,width,height,width*4,format);close(fd);
 struct ext_image_copy_capture_frame_v1 *frame=ext_image_copy_capture_session_v1_create_frame(session);
 ext_image_copy_capture_frame_v1_add_listener(frame,&frame_listener,NULL);ext_image_copy_capture_frame_v1_attach_buffer(frame,buffer);ext_image_copy_capture_frame_v1_damage_buffer(frame,0,0,width,height);ext_image_copy_capture_frame_v1_capture(frame);
 while(!finished)if(wl_display_dispatch(display)<0)return 8;
 if(failed)return 9;
 unsigned green=0,pink=0,black=0;
 for(size_t i=0;i<bytes;i+=4){unsigned b=pixels[i],g=pixels[i+1],r=pixels[i+2];green+=(g>r+30&&g>b+30);pink+=(r>g+30&&b>g+30);black+=(r==0&&g==0&&b==0);}
 printf("{\"protocol\":\"ext_image_copy_capture_v1\",\"width\":%u,\"height\":%u,\"green_private_pixels\":%u,\"pink_control_pixels\":%u,\"black_pixels\":%u}\n",width,height,green,pink,black);
 munmap(pixels,bytes);wl_display_disconnect(display);return 0;
}
